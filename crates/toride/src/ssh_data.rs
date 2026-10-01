//! Async SSH data collection via a tokio oneshot channel.
//!
//! Reads real SSH files via the `toride-ssh` library and falls back to empty
//! data when files are missing or unreadable. Mock data is `#[cfg(test)]`-only.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratatui::style::Color;
use tokio::sync::oneshot;

use crate::ssh_convert;
#[cfg(test)]
use crate::ui::screens::ssh::ForwardEntry;
use crate::ui::screens::ssh::{
    AgentKeyEntry, AgentStatus, AuthorizedKeyEntry, CertificateEntry, ConfigHostEntry,
    DiagnosticEntry, ForwardSessionEntry, KnownHostEntry, SshAccessInfo, SshKeyEntry,
    SystemUserInfo,
};
use crate::ui::theme::Palette;

/// Aggregated SSH data for all tabs.
pub struct SshDataBundle {
    /// SSH key entries.
    pub keys: Vec<SshKeyEntry>,
    /// Known hosts entries.
    pub known_hosts: Vec<KnownHostEntry>,
    /// SSH config host blocks.
    pub config_hosts: Vec<ConfigHostEntry>,
    /// SSH agent connection status.
    pub agent_status: AgentStatus,
    /// Keys loaded in the SSH agent.
    pub agent_keys: Vec<AgentKeyEntry>,
    /// Active port forwarding sessions.
    pub forwarding: Vec<ForwardSessionEntry>,
    /// Diagnostic check results.
    pub diagnostics: Arc<Vec<DiagnosticEntry>>,
    /// Authorized keys entries.
    pub authorized_keys: Vec<AuthorizedKeyEntry>,
    /// SSH certificate entries.
    pub certificates: Vec<CertificateEntry>,
    /// Security overview data.
    pub security: SshSecurityData,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct FileStamp {
    mtime_ns: u128,
    len: u64,
}

fn stamp_path(path: &Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime_ns = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(FileStamp {
        mtime_ns,
        len: meta.len(),
    })
}

struct Stamped<K, T> {
    stamp: K,
    value: Arc<T>,
}

#[derive(Clone)]
struct UserSshScan {
    ssh_key_count: usize,
    authorized_key_count: usize,
    authorized_keys_preview: Vec<crate::ui::screens::ssh::AuthorizedKeyPreview>,
}

#[derive(PartialEq, Clone)]
struct UserSshStamp {
    key_listing: Vec<(String, Option<FileStamp>)>,
    auth: Option<FileStamp>,
}

fn user_scan_cacheable(stamp: &UserSshStamp) -> bool {
    stamp.key_listing.iter().all(|(_, s)| s.is_some()) && stamp.auth.is_some()
}

pub(crate) struct SshStateCache {
    known_hosts: Mutex<Option<Stamped<FileStamp, Vec<KnownHostEntry>>>>,
    authorized_keys: Mutex<Option<Stamped<FileStamp, Vec<AuthorizedKeyEntry>>>>,
    certificates: Mutex<Option<CertCacheSlot>>,
    user_ssh_scans: Mutex<HashMap<PathBuf, Stamped<UserSshStamp, UserSshScan>>>,
}

type CertCacheSlot =
    Stamped<Vec<(PathBuf, FileStamp)>, Vec<(PathBuf, toride_ssh::certificate::CertificateInfo)>>;

impl SshStateCache {
    pub(crate) fn new() -> Self {
        Self {
            known_hosts: Mutex::new(None),
            authorized_keys: Mutex::new(None),
            certificates: Mutex::new(None),
            user_ssh_scans: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for SshStateCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages periodic async collection of SSH data.
pub struct SshDataCollector {
    rx: Option<oneshot::Receiver<(SshDataBundle, bool)>>,
    cached_diagnostics: Option<Arc<Vec<DiagnosticEntry>>>,
    diagnostics_fresh_at: Option<std::time::Instant>,
    state_cache: Arc<SshStateCache>,
}

const DIAGNOSTICS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

impl SshDataCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rx: None,
            cached_diagnostics: None,
            diagnostics_fresh_at: None,
            state_cache: Arc::new(SshStateCache::new()),
        }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_cache = self.cached_diagnostics.is_some()
            && self
                .diagnostics_fresh_at
                .is_some_and(|t| t.elapsed() < DIAGNOSTICS_TTL);
        let cached_diag = self.cached_diagnostics.clone();
        let state_cache = Arc::clone(&self.state_cache);
        self.rx = Some(rx);
        tokio::spawn(async move {
            let (bundle, cache_was_used) =
                collect_real_data(use_cache, cached_diag, &state_cache).await;
            let _ = tx.send((bundle, cache_was_used));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` on completion, `None` while pending or failed.
    pub async fn poll(&mut self) -> Option<SshDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, cache_was_used)) = result {
                    self.cached_diagnostics = Some(Arc::clone(&bundle.diagnostics));
                    if !cache_was_used {
                        self.diagnostics_fresh_at = Some(std::time::Instant::now());
                    }
                }
                self.rx = None;
                result.map(|(bundle, _)| bundle)
            }
            None => None,
        }
    }

    /// Invalidate the diagnostics cache so the next collection re-runs checks.
    pub fn invalidate_diagnostics_cache(&mut self) {
        self.cached_diagnostics = None;
        self.diagnostics_fresh_at = None;
    }
}

impl Default for SshDataCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// A pending write operation to be executed asynchronously via `SshManager`.
#[derive(Debug)]
pub enum SshOp {
    /// Add a host block to `~/.ssh/config`.
    ConfigAddHost {
        /// Host alias to define.
        name: String,
        /// Optional `HostName` value (real address).
        host_name: Option<String>,
        /// Optional `User` value (login user).
        user: Option<String>,
        /// Optional `Port` value.
        port: Option<u16>,
    },
    /// Remove a host block from `~/.ssh/config`.
    ConfigRemoveHost {
        /// Host alias to remove.
        name: String,
    },
    /// Edit (replace) a host block in `~/.ssh/config`.
    ConfigEditHost {
        /// Existing host alias to replace.
        old_name: String,
        /// New host alias.
        new_name: String,
        /// Optional `HostName` value (real address).
        host_name: Option<String>,
        /// Optional `User` value (login user).
        user: Option<String>,
        /// Optional `Port` value.
        port: Option<u16>,
    },
    /// Generate a new SSH key pair.
    KeyCreate {
        /// File name (without directory) for the new key.
        name: String,
        /// Key type as displayed by the UI (e.g. `"RSA 4096"`).
        key_type: String,
        /// Comment embedded in the new key.
        comment: String,
        /// Optional passphrase protecting the private key.
        passphrase: Option<String>,
    },
    /// Delete an SSH key pair.
    KeyDelete {
        /// File name (without directory) of the key to delete.
        name: String,
    },
    /// Rename an SSH key pair.
    KeyRename {
        /// Existing key file name.
        old_name: String,
        /// New key file name.
        new_name: String,
    },
    /// Add a host to `known_hosts` via ssh-keyscan.
    KnownHostAdd {
        /// Host (and optional `:port`) to scan and trust.
        host: String,
    },
    /// Remove a host from `known_hosts`.
    KnownHostRemove {
        /// Host (and optional `:port`) to remove.
        host: String,
    },
    /// Add a key to the SSH agent.
    AgentAddKey {
        /// Path to the private key file to load.
        path: String,
    },
    /// Remove a key from the SSH agent.
    AgentRemoveKey {
        /// Path to the private key file to unload.
        path: String,
    },
    /// Add a public key to `authorized_keys`.
    AuthorizedKeyAdd {
        /// OpenSSH-format public key blob.
        public_key: String,
        /// Optional trailing comment for the entry.
        comment: Option<String>,
        /// Optional comma-separated options string.
        options: Option<String>,
    },
    /// Remove a public key from `authorized_keys` by fingerprint.
    AuthorizedKeyRemove {
        /// SHA-256 fingerprint of the key(s) to remove.
        fingerprint: String,
    },
    /// Fix permissions on an SSH key pair.
    KeyChmodFix {
        /// File name (without directory) of the key to fix.
        name: String,
    },
    /// Scan a host for its SSH host keys.
    KnownHostScan {
        /// Host (and optional `:port`) to scan.
        host: String,
    },
    /// Hash all plaintext hostnames in `known_hosts`.
    KnownHostHashAll,
    /// Remove all keys from the SSH agent.
    AgentRemoveAll,
    /// Cancel a specific port forward on a control session.
    ForwardCancel {
        /// Control master socket path.
        control_path: String,
        /// Local port of the forward to cancel.
        local_port: u16,
    },
    /// Exit (terminate) a control master session.
    ForwardExitSession {
        /// Control master socket path.
        control_path: String,
    },
    /// Revoke a key by adding it to the KRL.
    CertificateRevoke {
        /// File name of the key/cert to revoke.
        name: String,
    },
    /// Run all local SSH diagnostic checks.
    DoctorRunChecks,
    /// Install a public key to a remote host.
    KeyInstallToRemote {
        /// Local key file name (without directory) to install.
        key_name: String,
        /// Remote `user@host[:port]` target.
        dest: String,
    },
    /// Test whether a passphrase unlocks an SSH key.
    KeyTestPassphrase {
        /// File name (without directory) of the key to test.
        name: String,
        /// Passphrase to verify against the key.
        passphrase: String,
    },
    /// Grant a user SSH login access by adding them to `AllowUsers` in
    /// `/etc/ssh/sshd_config` (and removing them from `DenyUsers` if present).
    SshdAllowUser {
        /// Username to grant access.
        username: String,
    },
    /// Revoke a user's SSH login access by adding them to `DenyUsers` in
    /// `/etc/ssh/sshd_config`.
    SshdDenyUser {
        /// Username to deny access.
        username: String,
    },
    /// Reset a user to the default access policy by removing them from both
    /// `AllowUsers` and `DenyUsers`.
    SshdResetUserAccess {
        /// Username to reset to default policy.
        username: String,
    },
}

/// A typed error from a write operation.
///
/// `revert_optimistic`: revert the optimistic UI update immediately (refresh)
/// rather than waiting out the write cooldown — disk truth is known to differ.
#[derive(Debug, Clone)]
pub struct SshOpError {
    /// Human-readable error message (also surfaced to the user as a toast).
    pub message: String,
    /// When true, the optimistic UI update should be reverted immediately by
    /// forcing an SSH data refresh instead of waiting for the write cooldown.
    pub revert_optimistic: bool,
}

impl SshOpError {
    #[allow(dead_code)]
    fn transient(message: String) -> Self {
        Self {
            message,
            revert_optimistic: false,
        }
    }

    fn reverting(message: String) -> Self {
        Self {
            message,
            revert_optimistic: true,
        }
    }
}

fn map_sshd_error(verb: &str, who: &str, e: &toride_ssh::Error) -> SshOpError {
    let message = format!("failed to {verb} '{who}': {e}");
    tracing::error!("sshd: {message}");
    let revert = matches!(
        e,
        toride_ssh::Error::SshdConfigInvalid(_)
            | toride_ssh::Error::SshdNotFound(_)
            | toride_ssh::Error::SudoFailed(_)
            | toride_ssh::Error::ConfigWriteFailed(_)
            | toride_ssh::Error::Io(_)
    );
    if revert {
        SshOpError::reverting(message)
    } else {
        SshOpError::transient(message)
    }
}

#[allow(dead_code)]
fn would_lock_out(verb: &str, username: &str) -> Option<SshOpError> {
    if username == "root" {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    if let Some(current) = current_username()
        && current == username
    {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    let euid = current_euid();
    let resolved_uid = uid_for_username(username);
    would_lock_out_with_uid(verb, username, euid, resolved_uid)
}

async fn would_lock_out_async(verb: &str, username: &str) -> Option<SshOpError> {
    if username == "root" {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    let verb = verb.to_string();
    let username = username.to_string();
    let verb_fallback = verb.clone();
    let username_fallback = username.clone();
    tokio::task::spawn_blocking(move || {
        if username == "root" {
            return Some(SshOpError::reverting(format!(
                "refusing to {verb} '{username}': would lock out root / your own account"
            )));
        }
        if let Some(current) = current_username()
            && current == username
        {
            return Some(SshOpError::reverting(format!(
                "refusing to {verb} '{username}': would lock out root / your own account"
            )));
        }
        let euid = current_euid();
        let resolved_uid = uid_for_username(&username);
        would_lock_out_with_uid(&verb, &username, euid, resolved_uid)
    })
    .await
    .unwrap_or_else(move |e| {
        tracing::error!(
            "would_lock_out blocking task panicked for '{username_fallback}': {e}; refusing"
        );
        Some(SshOpError::reverting(format!(
            "refusing to {verb_fallback} '{username_fallback}': lockout check failed ({e})"
        )))
    })
}

fn would_lock_out_with_uid(
    verb: &str,
    username: &str,
    euid: u32,
    resolved_uid: Option<u32>,
) -> Option<SshOpError> {
    if resolved_uid == Some(euid) {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    if resolved_uid == Some(0) {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    if resolved_uid.is_none() {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': cannot resolve account to a UID \
             (network account unavailable?); refusing to avoid a self-lockout"
        )));
    }
    None
}

#[cfg(unix)]
fn current_username() -> Option<String> {
    // SAFETY: geteuid is a trivial read with no preconditions.
    let euid = unsafe { libc::geteuid() };
    uid_to_username(euid)
}

#[cfg(not(unix))]
fn current_username() -> Option<String> {
    None
}

#[cfg(unix)]
fn current_euid() -> u32 {
    // SAFETY: geteuid is a trivial read with no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_euid() -> u32 {
    u32::MAX
}

async fn would_lock_out_authorized_key(
    svc: &toride_ssh::authorized_keys::AuthorizedKeysService<'_>,
    fingerprint: &str,
) -> Option<SshOpError> {
    let entries = match svc.list().await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                "authorized_keys self-lockout guard: refusing removal of \
                 '{fingerprint}' because the current entry list could not be \
                 read ({e})"
            );
            return Some(SshOpError::reverting(format!(
                "refusing to remove authorized key '{fingerprint}': could not \
                 verify a key would remain after removal ({e})"
            )));
        }
    };
    let total = entries.len();
    if total == 0 {
        return None;
    }
    let matching = entries
        .iter()
        .filter(|e| e.fingerprint().as_deref() == Some(fingerprint))
        .count();
    if matching >= total {
        Some(SshOpError::reverting(format!(
            "refusing to remove authorized key '{fingerprint}': it is the last \
             key in your authorized_keys (would lock you out of SSH)"
        )))
    } else {
        None
    }
}

fn uid_for_username(username: &str) -> Option<u32> {
    if let Some(uid) = nss_uid_for_username(username) {
        return Some(uid);
    }
    if cfg!(target_os = "macos") {
        if let Some(uid) = dscl_uid_for_username(username, "/Search") {
            return Some(uid);
        }
        if let Some(uid) = dscl_uid_for_username(username, ".") {
            return Some(uid);
        }
    }
    if let Some(uid) = id_uid_for_username(username) {
        return Some(uid);
    }
    passwd_uid_for_username(username)
}

fn uid_to_username(uid: u32) -> Option<String> {
    if let Some(name) = nss_username_for_uid(uid) {
        return Some(name);
    }
    if cfg!(target_os = "macos") {
        if let Some(name) = dscl_username_for_uid(uid, "/Search") {
            return Some(name);
        }
        if let Some(name) = dscl_username_for_uid(uid, ".") {
            return Some(name);
        }
    }
    if let Some(name) = getent_username_for_uid(uid) {
        return Some(name);
    }
    passwd_username_for_uid(uid)
}

#[cfg(unix)]
fn nss_uid_for_username(username: &str) -> Option<u32> {
    // SAFETY: getpwnam_r is thread-safe and reads `name` as a NUL-terminated
    // C string. We pass a freshly-allocated CString; the resulting `passwd`
    // pointer is only dereferenced synchronously before return.
    use std::ffi::CString;
    use std::ptr;
    if username.is_empty() {
        return None;
    }
    let c_name = CString::new(username).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = ptr::null_mut();
    let mut buflen: usize = 2048;
    loop {
        let mut buf = vec![0u8; buflen];
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &raw mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == libc::ERANGE {
            buflen = buflen.saturating_mul(2);
            if buflen > 65_536 {
                return None;
            }
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let uid = unsafe { (*result).pw_uid };
        return Some(uid);
    }
}

#[cfg(not(unix))]
fn nss_uid_for_username(_username: &str) -> Option<u32> {
    None
}

#[cfg(unix)]
fn nss_username_for_uid(uid: u32) -> Option<String> {
    use std::ffi::CStr;
    use std::ptr;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = ptr::null_mut();
    let mut buflen: usize = 2048;
    loop {
        let mut buf = vec![0u8; buflen];
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == libc::ERANGE {
            buflen = buflen.saturating_mul(2);
            if buflen > 65_536 {
                return None;
            }
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: pw_name points into `buf`, which is alive for this scope.
        // Copy to an owned String before the buffer is released.
        let name_ptr = unsafe { (*result).pw_name };
        if name_ptr.is_null() {
            return None;
        }
        let cstr = unsafe { CStr::from_ptr(name_ptr) };
        let name = cstr.to_str().ok()?;
        if name.is_empty() {
            return None;
        }
        return Some(name.to_owned());
    }
}

#[cfg(not(unix))]
fn nss_username_for_uid(_uid: u32) -> Option<String> {
    None
}

fn dscl_uid_for_username(username: &str, node: &str) -> Option<u32> {
    let out = std::process::Command::new("dscl")
        .args([node, "-read", &format!("/Users/{username}"), "UniqueID"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .find_map(|l| l.strip_prefix("UniqueID:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
}

fn dscl_username_for_uid(uid: u32, node: &str) -> Option<String> {
    let out = std::process::Command::new("dscl")
        .args([node, "-search", "/Users", "UniqueID", &uid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .next()
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_owned)
}

fn id_uid_for_username(username: &str) -> Option<u32> {
    if username.is_empty() {
        return None;
    }
    let out = std::process::Command::new("id")
        .args(["-u", username])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.trim().parse::<u32>().ok()
}

fn getent_username_for_uid(uid: u32) -> Option<String> {
    if cfg!(target_os = "macos") {
        return None;
    }
    let out = std::process::Command::new("getent")
        .args(["passwd", &uid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .next()
        .and_then(|line| line.split(':').next().map(std::borrow::ToOwned::to_owned))
}

fn passwd_uid_for_username(username: &str) -> Option<u32> {
    let contents = std::fs::read_to_string("/etc/passwd").ok()?;
    contents.lines().find_map(|line| {
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() < 3 || parts[0] != username {
            return None;
        }
        parts[2].parse::<u32>().ok()
    })
}

fn passwd_username_for_uid(uid: u32) -> Option<String> {
    let contents = std::fs::read_to_string("/etc/passwd").ok()?;
    contents.lines().find_map(|line| {
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() < 3 {
            return None;
        }
        (parts[2].parse::<u32>().ok() == Some(uid)).then(|| parts[0].to_owned())
    })
}

fn keygen_read_public_argv(key_path: &str) -> Vec<String> {
    vec!["-y".to_owned(), "-f".to_owned(), key_path.to_owned()]
}

fn check_key_passphrase(key_path: &Path, passphrase: &str) -> std::io::Result<bool> {
    let askpass = toride_ssh::agent::AskpassHandler::new(passphrase)
        .map_err(|e| std::io::Error::other(format!("askpass setup failed: {e}")))?;
    let argv = keygen_read_public_argv(&key_path.to_string_lossy());
    let status = std::process::Command::new("ssh-keygen")
        .args(&argv)
        .env("SSH_ASKPASS", askpass.script_path())
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(status.success())
}

fn finish_outcome<T, E: std::fmt::Display>(
    section: &str,
    success: String,
    fail_prefix: &str,
    result: Result<T, E>,
) -> Result<String, SshOpError> {
    match result {
        Ok(_) => {
            tracing::info!("{section}: {success}");
            Ok(success)
        }
        Err(e) => {
            let msg = format!("{fail_prefix}: {e}");
            tracing::error!("{section}: {msg}");
            Err(SshOpError::transient(msg))
        }
    }
}

/// Dispatch a UI SSH action to the backend.
///
/// # Errors
///
/// `Err(SshOpError)` on a write/validation failure or on `SshManager::new()` failure.
#[expect(
    clippy::too_many_lines,
    reason = "one match arm per SshOp variant; naturally large"
)]
pub async fn execute_op(op: SshOp) -> Result<String, SshOpError> {
    let mgr = match toride_ssh::SshManager::new() {
        Ok(m) => m,
        Err(e) => {
            let msg = format!("SSH init failed: {e}");
            tracing::error!("{msg}");
            return Err(SshOpError::transient(msg));
        }
    };

    match op {
        SshOp::ConfigAddHost {
            name,
            host_name,
            user,
            port,
        } => {
            let svc = mgr.config();
            let mut directives = Vec::new();
            if let Some(hn) = &host_name {
                directives.push(("HostName".to_string(), hn.clone()));
            }
            if let Some(u) = &user {
                directives.push(("User".to_string(), u.clone()));
            }
            if let Some(p) = port {
                directives.push(("Port".to_string(), p.to_string()));
            }
            finish_outcome(
                "config",
                format!("added host '{name}'"),
                &format!("failed to add host '{name}'"),
                svc.edit(|ast| toride_ssh::config::ConfigService::add_host(ast, &name, directives))
                    .await,
            )
        }
        SshOp::ConfigRemoveHost { name } => {
            let svc = mgr.config();
            finish_outcome(
                "config",
                format!("removed host '{name}'"),
                &format!("failed to remove host '{name}'"),
                svc.edit(|ast| toride_ssh::config::ConfigService::remove_host(ast, &name))
                    .await,
            )
        }
        SshOp::ConfigEditHost {
            old_name,
            new_name,
            host_name,
            user,
            port,
        } => {
            let svc = mgr.config();
            finish_outcome(
                "config",
                format!("edited host '{old_name}' → '{new_name}'"),
                &format!("failed to edit host '{old_name}'"),
                svc.edit(|ast| {
                    let _ = toride_ssh::config::ConfigService::remove_host(ast, &old_name);
                    let mut directives = Vec::new();
                    if let Some(hn) = &host_name {
                        directives.push(("HostName".to_string(), hn.clone()));
                    }
                    if let Some(u) = &user {
                        directives.push(("User".to_string(), u.clone()));
                    }
                    if let Some(p) = port {
                        directives.push(("Port".to_string(), p.to_string()));
                    }
                    toride_ssh::config::ConfigService::add_host(ast, &new_name, directives)
                })
                .await,
            )
        }
        SshOp::KeyCreate {
            name,
            key_type,
            comment,
            passphrase,
        } => {
            let svc = mgr.keys();
            let mut params = match key_type.as_str() {
                "RSA 4096" => toride_ssh::KeyCreateParams::rsa_4096(name.clone()),
                "ECDSA P-256" => {
                    let mut p = toride_ssh::KeyCreateParams::ed25519(name.clone());
                    p.key_type = toride_ssh::KeyType::EcdsaP256;
                    p
                }
                _ => toride_ssh::KeyCreateParams::ed25519(name.clone()),
            };
            if !comment.is_empty() {
                params.comment = Some(comment.clone());
            }
            if let Some(ref pw) = passphrase
                && !pw.is_empty()
            {
                params.passphrase = Some(pw.clone());
            }
            finish_outcome(
                "keys",
                format!("created key '{name}'"),
                &format!("failed to create key '{name}'"),
                svc.create(params).await,
            )
        }
        SshOp::KeyDelete { name } => {
            let svc = mgr.keys();
            let params = toride_ssh::KeyDeleteParams {
                name: name.clone(),
                remove_public: true,
                remove_certificate: true,
                remove_from_agent: true,
                remove_from_config: true,
                backup: false,
            };
            finish_outcome(
                "keys",
                format!("deleted key '{name}'"),
                &format!("failed to delete key '{name}'"),
                svc.delete(params).await,
            )
        }
        SshOp::KeyRename { old_name, new_name } => {
            let svc = mgr.keys();
            finish_outcome(
                "keys",
                format!("renamed '{old_name}' → '{new_name}'"),
                &format!("failed to rename '{old_name}'"),
                svc.rename(&old_name, &new_name).await,
            )
        }
        SshOp::KnownHostAdd { host } => {
            let svc = mgr.known_hosts();
            finish_outcome(
                "known_hosts",
                format!("added known host '{host}'"),
                &format!("failed to add known host '{host}'"),
                svc.add(&host).await,
            )
        }
        SshOp::KnownHostRemove { host } => {
            let svc = mgr.known_hosts();
            finish_outcome(
                "known_hosts",
                format!("removed known host '{host}'"),
                &format!("failed to remove known host '{host}'"),
                svc.remove(&host).await,
            )
        }
        SshOp::AgentAddKey { path } => {
            let svc = mgr.agent();
            let path_ref = std::path::Path::new(&path);
            finish_outcome(
                "agent",
                format!("added key to agent: '{path}'"),
                &format!("failed to add key '{path}' to agent"),
                svc.add_key(path_ref).await,
            )
        }
        SshOp::AgentRemoveKey { path } => {
            let svc = mgr.agent();
            let path_ref = std::path::Path::new(&path);
            finish_outcome(
                "agent",
                format!("removed key from agent: '{path}'"),
                &format!("failed to remove key '{path}' from agent"),
                svc.remove_key(path_ref).await,
            )
        }
        SshOp::AuthorizedKeyAdd {
            public_key,
            comment,
            options,
        } => {
            let svc = mgr.authorized_keys();
            finish_outcome(
                "authorized_keys",
                "added authorized key".to_string(),
                "failed to add authorized key",
                svc.add(&public_key, comment.as_deref(), options.as_deref())
                    .await,
            )
        }
        SshOp::AuthorizedKeyRemove { fingerprint } => {
            let svc = mgr.authorized_keys();
            if let Some(err) = would_lock_out_authorized_key(&svc, &fingerprint).await {
                return Err(err);
            }
            match svc.remove(&fingerprint).await {
                Ok(n) => {
                    tracing::info!("authorized_keys: removed {n} key(s) matching '{fingerprint}'");
                    Ok(format!("removed {n} authorized key(s)"))
                }
                Err(e) => {
                    let msg = format!("failed to remove authorized key '{fingerprint}': {e}");
                    tracing::error!("authorized_keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::KeyChmodFix { name } => {
            let svc = mgr.keys();
            finish_outcome(
                "keys",
                format!("fixed permissions on '{name}'"),
                &format!("failed to fix permissions on '{name}'"),
                svc.chmod_fix(&name).await,
            )
        }
        SshOp::KnownHostScan { host } => {
            let svc = mgr.known_hosts();
            match svc.scan(&host).await {
                Ok(keys) => {
                    tracing::info!("known_hosts: scanned '{host}' ({} key(s))", keys.len());
                    Ok(format!("scanned '{host}' ({} key(s))", keys.len()))
                }
                Err(e) => {
                    let msg = format!("failed to scan host '{host}': {e}");
                    tracing::error!("known_hosts: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::KnownHostHashAll => {
            let svc = mgr.known_hosts();
            finish_outcome(
                "known_hosts",
                "hashed all known hostnames".to_string(),
                "failed to hash all known hostnames",
                svc.hash_all().await,
            )
        }
        SshOp::AgentRemoveAll => {
            let svc = mgr.agent();
            finish_outcome(
                "agent",
                "removed all keys from agent".to_string(),
                "failed to remove all keys from agent",
                svc.remove_all().await,
            )
        }
        SshOp::ForwardCancel {
            control_path,
            local_port,
        } => {
            let svc = mgr.forward();
            let path = std::path::Path::new(&control_path);
            finish_outcome(
                "forward",
                format!("cancelled forward on port {local_port}"),
                &format!("failed to cancel forward on port {local_port}"),
                svc.cancel(path, local_port).await,
            )
        }
        SshOp::ForwardExitSession { control_path } => {
            let svc = mgr.forward();
            let path = std::path::Path::new(&control_path);
            finish_outcome(
                "forward",
                format!("exited session '{control_path}'"),
                &format!("failed to exit session '{control_path}'"),
                svc.exit_session(path).await,
            )
        }
        SshOp::CertificateRevoke { name } => {
            let svc = mgr.certificate();
            let krl_str = toride_ssh::SshPaths::new().map_or_else(
                |_| {
                    format!(
                        "{}/.ssh/revoked_keys",
                        std::env::var("HOME").unwrap_or_default()
                    )
                },
                |p| {
                    p.ssh_dir()
                        .join("revoked_keys")
                        .to_string_lossy()
                        .into_owned()
                },
            );
            let krl_path = std::path::Path::new(&krl_str);
            finish_outcome(
                "certificates",
                format!("revoked key '{name}'"),
                &format!("failed to revoke key '{name}'"),
                svc.revoke_key(krl_path, &name).await,
            )
        }
        SshOp::DoctorRunChecks => {
            let svc = mgr.doctor();
            match svc.run_local_checks().await {
                Ok(diagnostics) => {
                    tracing::info!(
                        "doctor: ran local checks ({} finding(s))",
                        diagnostics.len()
                    );
                    Ok(serde_json::to_string(&diagnostics).unwrap_or_default())
                }
                Err(e) => {
                    let msg = format!("failed to run local checks: {e}");
                    tracing::error!("doctor: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::KeyInstallToRemote { key_name, dest } => {
            let svc = mgr.keys();
            let ssh_dir = match toride_ssh::SshPaths::new() {
                Ok(p) => p.ssh_dir().to_path_buf(),
                Err(e) => {
                    let msg = format!("failed to resolve SSH directory: {e}");
                    tracing::error!("keys: {msg}");
                    return Err(SshOpError::transient(msg));
                }
            };
            let key_path = ssh_dir.join(&key_name);
            finish_outcome(
                "keys",
                format!("installed '{key_name}' to '{dest}'"),
                &format!("failed to install '{key_name}' to '{dest}'"),
                svc.install_key_to_remote(&key_path, &dest).await,
            )
        }
        SshOp::KeyTestPassphrase { name, passphrase } => {
            let ssh_dir = match toride_ssh::SshPaths::new() {
                Ok(p) => p.ssh_dir().to_path_buf(),
                Err(e) => {
                    let msg = format!("failed to resolve SSH directory: {e}");
                    tracing::error!("keys: {msg}");
                    return Err(SshOpError::transient(msg));
                }
            };
            let key_path = ssh_dir.join(&name);
            let pw = passphrase;
            let path_for_task = key_path.clone();
            let result =
                tokio::task::spawn_blocking(move || check_key_passphrase(&path_for_task, &pw))
                    .await;
            match result {
                Ok(Ok(true)) => {
                    tracing::info!("keys: passphrase correct for '{name}'");
                    Ok(format!("passphrase correct for '{name}'"))
                }
                Ok(Ok(false)) => {
                    let msg = format!("wrong passphrase for '{name}'");
                    tracing::warn!("keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
                Ok(Err(e)) => {
                    let msg = format!("failed to test passphrase for '{name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
                Err(e) => {
                    let msg = format!("task join error testing passphrase for '{name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::SshdAllowUser { username } => {
            let is_root = toride_ssh::is_root();
            let result = toride_ssh::config::sshd::edit(is_root, |ast| {
                toride_ssh::config::sshd::add_user_to_allow(ast, &username)?;
                toride_ssh::config::sshd::remove_user_from_deny(ast, &username)?;
                Ok(())
            })
            .await;
            match result {
                Ok(()) => {
                    tracing::info!("sshd: granted login access to '{username}'");
                    Ok(format!("granted login access to '{username}'"))
                }
                Err(e) => Err(map_sshd_error("allow", &username, &e)),
            }
        }
        SshOp::SshdDenyUser { username } => {
            if let Some(err) = would_lock_out_async("deny", &username).await {
                return Err(err);
            }
            let is_root = toride_ssh::is_root();
            let result = toride_ssh::config::sshd::edit(is_root, |ast| {
                toride_ssh::config::sshd::add_user_to_deny(ast, &username)?;
                toride_ssh::config::sshd::remove_user_from_allow(ast, &username)?;
                Ok(())
            })
            .await;
            match result {
                Ok(()) => {
                    tracing::info!("sshd: revoked login access for '{username}'");
                    Ok(format!("revoked login access for '{username}'"))
                }
                Err(e) => Err(map_sshd_error("deny", &username, &e)),
            }
        }
        SshOp::SshdResetUserAccess { username } => {
            if let Some(err) = would_lock_out_async("reset", &username).await {
                return Err(err);
            }
            let is_root = toride_ssh::is_root();
            let result = toride_ssh::config::sshd::edit(is_root, |ast| {
                toride_ssh::config::sshd::remove_user_from_allow(ast, &username)?;
                toride_ssh::config::sshd::remove_user_from_deny(ast, &username)?;
                Ok(())
            })
            .await;
            match result {
                Ok(()) => {
                    tracing::info!("sshd: reset access for '{username}'");
                    Ok(format!("reset access for '{username}'"))
                }
                Err(e) => Err(map_sshd_error("reset", &username, &e)),
            }
        }
    }
}

async fn collect_real_data(
    use_cache: bool,
    cached_diag: Option<Arc<Vec<DiagnosticEntry>>>,
    cache: &Arc<SshStateCache>,
) -> (SshDataBundle, bool) {
    let mgr = match toride_ssh::SshManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("SshManager::new() failed: {e}");
            return (empty_bundle(), false);
        }
    };
    let paths = toride_ssh::SshPaths::new().ok();

    let (keys_r, known_hosts_r, auth_keys_r, config_r, diag_r, agent_r, forward_r, cert_r) = tokio::join!(
        collect_keys(&mgr),
        collect_known_hosts_cached(&mgr, paths.as_ref(), cache),
        collect_authorized_keys_cached(&mgr, paths.as_ref(), cache),
        collect_config_hosts(&mgr),
        async {
            if use_cache {
                None
            } else {
                Some(collect_diagnostics(&mgr).await)
            }
        },
        collect_agent(&mgr),
        collect_forwarding(&mgr),
        collect_certificates_cached(&mgr, cache),
    );

    let keys = keys_r.unwrap_or_default();
    let known_hosts = known_hosts_r.unwrap_or_default();
    let authorized_keys = auth_keys_r.clone().unwrap_or_default();
    let config_hosts = config_r.unwrap_or_default();
    let diagnostics = if use_cache {
        cached_diag.unwrap_or_else(|| Arc::new(Vec::new()))
    } else {
        Arc::new(diag_r.and_then(std::result::Result::ok).unwrap_or_default())
    };

    let (agent_status, agent_keys) = agent_r.unwrap_or_else(|()| {
        (
            AgentStatus {
                reachable: false,
                socket_path: None,
                key_count: 0,
            },
            Vec::new(),
        )
    });
    let forwarding = forward_r.unwrap_or_default();
    let certificates = cert_r.unwrap_or_default();

    let security = {
        let known_hosts = known_hosts.clone();
        let authorized_keys = authorized_keys.clone();
        let diagnostics = Arc::clone(&diagnostics);
        let current_ssh_dir = paths.as_ref().map(|p| p.ssh_dir().to_path_buf());
        let current_entries = auth_keys_r.ok();
        let cache = Arc::clone(cache);
        tokio::task::spawn_blocking(move || {
            build_security_data(
                &known_hosts,
                &authorized_keys,
                &diagnostics,
                current_ssh_dir.as_deref(),
                current_entries.as_deref(),
                &cache,
            )
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("security data collection panicked: {e}");
            fallback_security_data()
        })
    };

    (
        SshDataBundle {
            keys,
            known_hosts,
            config_hosts,
            agent_status,
            agent_keys,
            forwarding,
            diagnostics,
            authorized_keys,
            certificates,
            security,
        },
        use_cache,
    )
}

fn fallback_security_data() -> SshSecurityData {
    SshSecurityData {
        sshd_config: HashMap::new(),
        authorized_key_count: 0,
        authorized_key_labels: Vec::new(),
        known_hosts_count: 0,
        known_hosts_hashed_count: 0,
        security_diagnostics: Vec::new(),
        access_info: SshAccessInfo {
            available: true,
            allowed_users: vec![],
            denied_users: vec![],
            allowed_groups: vec![],
            denied_groups: vec![],
            auth_methods: vec![],
            password_auth: true,
            pubkey_auth: true,
            permit_root_login: "prohibit-password".to_string(),
        },
        system_users: Vec::new(),
        is_root: toride_ssh::is_root(),
    }
}

fn empty_bundle() -> SshDataBundle {
    SshDataBundle {
        keys: Vec::new(),
        known_hosts: Vec::new(),
        config_hosts: Vec::new(),
        agent_status: AgentStatus {
            reachable: false,
            socket_path: None,
            key_count: 0,
        },
        agent_keys: Vec::new(),
        forwarding: Vec::new(),
        diagnostics: Arc::new(Vec::new()),
        authorized_keys: Vec::new(),
        certificates: Vec::new(),
        security: SshSecurityData {
            sshd_config: HashMap::new(),
            authorized_key_count: 0,
            authorized_key_labels: Vec::new(),
            known_hosts_count: 0,
            known_hosts_hashed_count: 0,
            security_diagnostics: Vec::new(),
            access_info: SshAccessInfo {
                available: false,
                allowed_users: vec![],
                denied_users: vec![],
                allowed_groups: vec![],
                denied_groups: vec![],
                auth_methods: vec![],
                password_auth: true,
                pubkey_auth: true,
                permit_root_login: "prohibit-password".to_string(),
            },
            system_users: Vec::new(),
            is_root: toride_ssh::is_root(),
        },
    }
}

async fn collect_known_hosts(mgr: &toride_ssh::SshManager) -> Result<Vec<KnownHostEntry>, ()> {
    let svc = mgr.known_hosts();
    match svc.list().await {
        Ok(entries) => Ok(ssh_convert::convert_known_hosts(&entries)),
        Err(e) => {
            tracing::warn!("known_hosts: {e}");
            Err(())
        }
    }
}

async fn collect_known_hosts_cached(
    mgr: &toride_ssh::SshManager,
    paths: Option<&toride_ssh::SshPaths>,
    cache: &SshStateCache,
) -> Result<Vec<KnownHostEntry>, ()> {
    let stamp = paths
        .map(toride_ssh::SshPaths::known_hosts_path)
        .and_then(stamp_path);
    if let Some(stamp) = stamp {
        let hit = {
            let slot = cache
                .known_hosts
                .lock()
                .expect("known_hosts cache mutex poisoned");
            slot.as_ref()
                .filter(|cached| cached.stamp == stamp)
                .map(|cached| Arc::clone(&cached.value))
        };
        if let Some(entries) = hit {
            return Ok((*entries).clone());
        }
    }

    let entries = collect_known_hosts(mgr).await?;

    if let Some(stamp) = stamp {
        *cache
            .known_hosts
            .lock()
            .expect("known_hosts cache mutex poisoned") = Some(Stamped {
            stamp,
            value: Arc::new(entries.clone()),
        });
    }
    Ok(entries)
}

async fn collect_authorized_keys(
    mgr: &toride_ssh::SshManager,
) -> Result<Vec<AuthorizedKeyEntry>, ()> {
    let svc = mgr.authorized_keys();
    match svc.list().await {
        Ok(entries) => Ok(ssh_convert::convert_authorized_keys(entries)),
        Err(e) => {
            tracing::warn!("authorized_keys: {e}");
            Err(())
        }
    }
}

async fn collect_authorized_keys_cached(
    mgr: &toride_ssh::SshManager,
    paths: Option<&toride_ssh::SshPaths>,
    cache: &SshStateCache,
) -> Result<Vec<AuthorizedKeyEntry>, ()> {
    let stamp = paths
        .map(toride_ssh::SshPaths::authorized_keys_path)
        .and_then(stamp_path);
    if let Some(stamp) = stamp {
        let hit = {
            let slot = cache
                .authorized_keys
                .lock()
                .expect("authorized_keys cache mutex poisoned");
            slot.as_ref()
                .filter(|cached| cached.stamp == stamp)
                .map(|cached| Arc::clone(&cached.value))
        };
        if let Some(entries) = hit {
            return Ok((*entries).clone());
        }
    }

    let entries = collect_authorized_keys(mgr).await?;

    if let Some(stamp) = stamp {
        *cache
            .authorized_keys
            .lock()
            .expect("authorized_keys cache mutex poisoned") = Some(Stamped {
            stamp,
            value: Arc::new(entries.clone()),
        });
    }
    Ok(entries)
}

async fn collect_keys(mgr: &toride_ssh::SshManager) -> Result<Vec<SshKeyEntry>, ()> {
    let svc = mgr.keys();
    match svc.list().await {
        Ok(keys) => Ok(ssh_convert::convert_keys(keys)),
        Err(e) => {
            tracing::warn!("keys: {e}");
            Err(())
        }
    }
}

async fn collect_config_hosts(mgr: &toride_ssh::SshManager) -> Result<Vec<ConfigHostEntry>, ()> {
    let svc = mgr.config();
    match svc.load().await {
        Ok(ast) => Ok(ssh_convert::convert_config_ast(&ast)),
        Err(e) => {
            tracing::warn!("config: {e}");
            Err(())
        }
    }
}

async fn collect_diagnostics(mgr: &toride_ssh::SshManager) -> Result<Vec<DiagnosticEntry>, ()> {
    let svc = mgr.doctor();
    match svc.run_local_checks().await {
        Ok(diagnostics) => Ok(ssh_convert::convert_diagnostics(diagnostics)),
        Err(e) => {
            tracing::warn!("doctor: {e}");
            Err(())
        }
    }
}

async fn collect_agent(
    mgr: &toride_ssh::SshManager,
) -> Result<(AgentStatus, Vec<AgentKeyEntry>), ()> {
    let svc = mgr.agent();
    let socket_path = std::env::var("SSH_AUTH_SOCK").ok();

    let reachable = match svc.status().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("agent status: {e}");
            false
        }
    };

    if !reachable {
        return Ok((
            AgentStatus {
                reachable: false,
                socket_path,
                key_count: 0,
            },
            Vec::new(),
        ));
    }

    match svc.list_keys().await {
        Ok(keys) => Ok(ssh_convert::convert_agent_keys(keys, true, socket_path)),
        Err(e) => {
            tracing::warn!("agent keys: {e}");
            Ok((
                AgentStatus {
                    reachable: true,
                    socket_path,
                    key_count: 0,
                },
                Vec::new(),
            ))
        }
    }
}

async fn collect_forwarding(mgr: &toride_ssh::SshManager) -> Result<Vec<ForwardSessionEntry>, ()> {
    let svc = mgr.forward();
    match svc.list().await {
        Ok(sessions) => Ok(ssh_convert::convert_forwarding(sessions)),
        Err(e) => {
            tracing::debug!("forwarding: {e}");
            Err(())
        }
    }
}

async fn collect_certificates_cached(
    mgr: &toride_ssh::SshManager,
    cache: &SshStateCache,
) -> Result<Vec<CertificateEntry>, ()> {
    let ssh_dir = match toride_ssh::SshPaths::new() {
        Ok(p) => p.ssh_dir().to_path_buf(),
        Err(_) => return Ok(Vec::new()),
    };

    let cert_files: Vec<(PathBuf, Option<FileStamp>)> = match std::fs::read_dir(&ssh_dir) {
        Ok(entries) => entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("-cert.pub"))
            })
            .map(|p| {
                let stamp = stamp_path(&p);
                (p, stamp)
            })
            .collect(),
        Err(_) => return Ok(Vec::new()),
    };

    if cert_files.is_empty() {
        return Ok(Vec::new());
    }

    let mut key: Vec<(PathBuf, FileStamp)> = cert_files
        .iter()
        .filter_map(|(p, s)| s.map(|s| (p.clone(), s)))
        .collect();
    key.sort();

    if cert_files.iter().all(|(_, s)| s.is_some()) {
        let hit = {
            let slot = cache
                .certificates
                .lock()
                .expect("certificates cache mutex poisoned");
            slot.as_ref()
                .filter(|cached| cached.stamp == key)
                .map(|cached| Arc::clone(&cached.value))
        };
        if let Some(raw) = hit {
            return Ok(ssh_convert::convert_certificates((*raw).clone()));
        }
    }

    let cert_svc = mgr.certificate();
    let mut raw = Vec::new();

    for (path, _) in &cert_files {
        match cert_svc.inspect(path).await {
            Ok(info) => raw.push((path.clone(), info)),
            Err(e) => {
                tracing::debug!(
                    "certificate {}: {e}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
            }
        }
    }

    if cert_files.iter().all(|(_, s)| s.is_some()) {
        *cache
            .certificates
            .lock()
            .expect("certificates cache mutex poisoned") = Some(Stamped {
            stamp: key,
            value: Arc::new(raw.clone()),
        });
    }

    Ok(ssh_convert::convert_certificates(raw))
}

fn build_security_data(
    known_hosts: &[KnownHostEntry],
    authorized_keys: &[AuthorizedKeyEntry],
    diagnostics: &[DiagnosticEntry],
    current_ssh_dir: Option<&Path>,
    current_entries: Option<&[AuthorizedKeyEntry]>,
    cache: &SshStateCache,
) -> SshSecurityData {
    let sshd_contents =
        std::fs::read_to_string(Path::new("/etc/ssh/sshd_config")).unwrap_or_default();

    let sshd_config = parse_sshd_config_from(&sshd_contents);

    let known_hosts_hashed_count = known_hosts.iter().filter(|h| h.is_hashed).count();

    let authorized_key_labels: Vec<String> = authorized_keys
        .iter()
        .map(|k| k.comment.clone().unwrap_or_else(|| "(no comment)".into()))
        .collect();

    let security_diagnostics: Vec<DiagnosticEntry> = diagnostics
        .iter()
        .filter(|d| d.severity == "warning" || d.severity == "error")
        .cloned()
        .collect();

    SshSecurityData {
        sshd_config,
        authorized_key_count: authorized_keys.len(),
        authorized_key_labels,
        known_hosts_count: known_hosts.len(),
        known_hosts_hashed_count,
        security_diagnostics,
        access_info: parse_sshd_access_info_from(&sshd_contents),
        system_users: parse_system_users(current_ssh_dir, current_entries, cache),
        is_root: toride_ssh::is_root(),
    }
}

/// Security grade computed from `sshd_config` and diagnostic results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityGrade {
    /// Excellent: minimal insecure settings.
    A,
    /// Good.
    B,
    /// Fair.
    C,
    /// Poor.
    D,
    /// Failing: critically insecure.
    F,
}

impl SecurityGrade {
    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SecurityGrade::A => "A",
            SecurityGrade::B => "B",
            SecurityGrade::C => "C",
            SecurityGrade::D => "D",
            SecurityGrade::F => "F",
        }
    }

    /// Palette color for the grade.
    #[must_use]
    pub fn color(self, p: Palette) -> Color {
        match self {
            SecurityGrade::A => p.ok,
            SecurityGrade::B => p.accent3,
            SecurityGrade::C | SecurityGrade::D => p.warn,
            SecurityGrade::F => p.err,
        }
    }
}

/// A single security check result for the dashboard.
#[derive(Clone, Debug)]
pub struct SecurityCheck {
    /// Human-readable label (e.g. "Password authentication").
    pub label: String,
    /// Current value (e.g. "no", "yes", "22").
    pub detail: String,
    /// Whether this setting is in a secure/passing state.
    pub passing: bool,
    /// Whether this is informational (not a pass/fail check).
    pub informational: bool,
}

/// Aggregated security data for the overview dashboard.
#[derive(Clone, Debug)]
pub struct SshSecurityData {
    /// Parsed `sshd_config` key-value pairs.
    pub sshd_config: HashMap<String, String>,
    /// Number of authorized keys.
    pub authorized_key_count: usize,
    /// Authorized key comments for listing.
    pub authorized_key_labels: Vec<String>,
    /// Number of entries in `known_hosts`.
    pub known_hosts_count: usize,
    /// How many `known_hosts` entries have hashed hostnames.
    pub known_hosts_hashed_count: usize,
    /// Security-relevant diagnostics (warnings/errors only).
    pub security_diagnostics: Vec<DiagnosticEntry>,
    /// Access control information parsed from `sshd_config`.
    pub access_info: SshAccessInfo,
    /// System users with valid login shells and SSH key info.
    pub system_users: Vec<SystemUserInfo>,
    /// Whether the app is running as root (drives edit capability for
    /// `sshd_config` and other users' `authorized_keys`).
    pub is_root: bool,
}

fn sshd_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" => Some(true),
        "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

fn sshd_bool_is(stored: Option<&String>, want: bool, default_when_unset: bool) -> bool {
    match stored.and_then(|v| sshd_bool(v)) {
        Some(b) => b == want,
        None => default_when_unset,
    }
}

impl SshSecurityData {
    /// Compute an overall security grade.
    #[must_use]
    pub fn grade(&self) -> SecurityGrade {
        let mut score = 100u32;
        let cfg = &self.sshd_config;

        if !sshd_bool_is(cfg.get("passwordauthentication"), false, false) {
            score -= 25;
        }
        if sshd_bool_is(cfg.get("permitrootlogin"), true, false) {
            score -= 20;
        }
        if sshd_bool_is(cfg.get("permitemptypasswords"), true, false) {
            score -= 15;
        }
        if sshd_bool_is(cfg.get("pubkeyauthentication"), false, false) {
            score -= 15;
        }
        let warn_count = u32::try_from(
            self.security_diagnostics
                .iter()
                .filter(|d| d.severity == "warning" || d.severity == "error")
                .count(),
        )
        .unwrap_or(u32::MAX);
        score -= warn_count.min(5) * 5;

        match score {
            90..=100 => SecurityGrade::A,
            75..=89 => SecurityGrade::B,
            55..=74 => SecurityGrade::C,
            35..=54 => SecurityGrade::D,
            _ => SecurityGrade::F,
        }
    }

    /// Individual check results for the dashboard.
    #[must_use]
    pub fn checks(&self) -> Vec<SecurityCheck> {
        let cfg = &self.sshd_config;
        vec![
            SecurityCheck {
                label: "Password authentication".into(),
                detail: cfg
                    .get("passwordauthentication")
                    .cloned()
                    .unwrap_or_else(|| "yes (default)".into()),
                passing: sshd_bool_is(cfg.get("passwordauthentication"), false, false),
                informational: false,
            },
            SecurityCheck {
                label: "Root login".into(),
                detail: cfg
                    .get("permitrootlogin")
                    .cloned()
                    .unwrap_or_else(|| "prohibit-password (default)".into()),
                passing: !sshd_bool_is(cfg.get("permitrootlogin"), true, false),
                informational: false,
            },
            SecurityCheck {
                label: "SSH port".into(),
                detail: cfg
                    .get("port")
                    .cloned()
                    .unwrap_or_else(|| "22 (default)".into()),
                passing: true,
                informational: true,
            },
            SecurityCheck {
                label: "Public key auth".into(),
                detail: cfg
                    .get("pubkeyauthentication")
                    .cloned()
                    .unwrap_or_else(|| "yes (default)".into()),
                passing: !sshd_bool_is(cfg.get("pubkeyauthentication"), false, false),
                informational: false,
            },
            SecurityCheck {
                label: "Max auth attempts".into(),
                detail: cfg
                    .get("maxauthtries")
                    .cloned()
                    .unwrap_or_else(|| "6 (default)".into()),
                passing: true,
                informational: true,
            },
            SecurityCheck {
                label: "Agent forwarding".into(),
                detail: cfg
                    .get("allowagentforwarding")
                    .cloned()
                    .unwrap_or_else(|| "yes (default)".into()),
                passing: sshd_bool_is(cfg.get("allowagentforwarding"), false, false),
                informational: false,
            },
            SecurityCheck {
                label: "X11 forwarding".into(),
                detail: cfg
                    .get("x11forwarding")
                    .cloned()
                    .unwrap_or_else(|| "no (default)".into()),
                passing: !sshd_bool_is(cfg.get("x11forwarding"), true, false),
                informational: false,
            },
            SecurityCheck {
                label: "Empty passwords".into(),
                detail: cfg
                    .get("permitemptypasswords")
                    .cloned()
                    .unwrap_or_else(|| "no (default)".into()),
                passing: !sshd_bool_is(cfg.get("permitemptypasswords"), true, false),
                informational: false,
            },
        ]
    }
}

#[allow(dead_code)]
fn parse_sshd_config() -> HashMap<String, String> {
    let contents = std::fs::read_to_string(Path::new("/etc/ssh/sshd_config")).unwrap_or_default();
    parse_sshd_config_from(&contents)
}

fn parse_sshd_config_from(contents: &str) -> HashMap<String, String> {
    parse_sshd_config_from_dir(contents, Path::new("/etc/ssh"))
}

fn parse_sshd_config_from_dir(contents: &str, base_dir: &Path) -> HashMap<String, String> {
    use toride_ssh::config::ast::{ConfigNode, parse};

    fn walk(
        ast_nodes: &[ConfigNode],
        base_dir: &Path,
        config: &mut HashMap<String, String>,
        seen: &mut std::collections::HashSet<std::path::PathBuf>,
    ) {
        for node in ast_nodes {
            let ConfigNode::Directive(d) = node else {
                continue;
            };
            let key = d.keyword.to_lowercase();
            if key == "include" {
                expand_include(&d.value, base_dir, config, seen);
                continue;
            }
            config.entry(key).or_insert_with(|| d.value.clone());
        }
    }

    fn expand_include(
        args: &str,
        base_dir: &Path,
        config: &mut HashMap<String, String>,
        seen: &mut std::collections::HashSet<std::path::PathBuf>,
    ) {
        for pattern in args.split_whitespace() {
            let resolved = resolve_include_path(pattern, base_dir);
            for file in glob_include(&resolved) {
                let canon = std::fs::canonicalize(&file).unwrap_or_else(|_| file.clone());
                if !seen.insert(canon.clone()) {
                    continue;
                }
                let Ok(contents) = std::fs::read_to_string(&file) else {
                    continue;
                };
                let child_ast = parse(&contents);
                walk(&child_ast.nodes, base_dir, config, seen);
            }
        }
    }

    let ast = parse(contents);
    let mut config: HashMap<String, String> = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    walk(&ast.nodes, base_dir, &mut config, &mut seen);
    config
}

fn resolve_include_path(pattern: &str, base_dir: &Path) -> std::path::PathBuf {
    let p = Path::new(pattern);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

fn glob_include(pattern: &Path) -> Vec<std::path::PathBuf> {
    let pattern_str = pattern.to_string_lossy().into_owned();
    let mut out = Vec::new();

    if let Some(idx) = pattern_str.find("**/") {
        let prefix = Path::new(&pattern_str[..idx]);
        let suffix = pattern_str[idx + 3..].trim_start_matches('/');
        collect_glob_recursive(prefix, suffix, &mut out);
        out.sort();
        return out;
    }

    let parent = pattern.parent().unwrap_or_else(|| Path::new("."));
    let file_pattern = pattern
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();

    if file_pattern.is_empty() {
        return out;
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_glob_match(&name_str, &file_pattern) && entry.path().is_file() {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

fn collect_glob_recursive(dir: &Path, suffix: &str, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let collected: Vec<_> = entries.flatten().collect();
    for entry in &collected {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if let Some(slash) = suffix.find('/') {
            let first = &suffix[..slash];
            let rest = &suffix[slash + 1..];
            if path.is_dir() && name_glob_match(&name_str, first) {
                collect_glob_recursive(&path, rest, out);
            }
        } else if name_glob_match(&name_str, suffix) && path.is_file() {
            out.push(path.clone());
        }

        if path.is_dir() {
            collect_glob_recursive(&path, suffix, out);
        }
    }
}

fn name_glob_match(name: &str, pattern: &str) -> bool {
    glob_match_inner(name.as_bytes(), pattern.as_bytes())
}

#[allow(clippy::similar_names, reason = "glob-matcher backtracking indices")]
fn glob_match_inner(text: &[u8], pattern: &[u8]) -> bool {
    let (mut ti, mut pi) = (0usize, 0usize);
    #[allow(clippy::similar_names, reason = "glob-matcher backtracking indices")]
    let (mut star_ti, mut star_pi) = (usize::MAX, usize::MAX);
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[allow(dead_code)]
fn parse_sshd_access_info() -> SshAccessInfo {
    let contents = std::fs::read_to_string(Path::new("/etc/ssh/sshd_config")).unwrap_or_default();
    parse_sshd_access_info_from(&contents)
}

fn parse_sshd_access_info_from(contents: &str) -> SshAccessInfo {
    use toride_ssh::config::ast::{ConfigNode, parse};
    use toride_ssh::config::sshd::{
        get_allow_groups, get_allow_users, get_deny_groups, get_deny_users,
    };

    let ast = parse(contents);

    let mut info = SshAccessInfo {
        available: true,
        ..SshAccessInfo::default()
    };

    info.allowed_users = get_allow_users(&ast);
    info.denied_users = get_deny_users(&ast);
    info.allowed_groups = get_allow_groups(&ast);
    info.denied_groups = get_deny_groups(&ast);

    let mut seen_pubkey = false;
    let mut seen_password = false;
    let mut seen_permit_root = false;

    for node in &ast.nodes {
        let ConfigNode::Directive(d) = node else {
            continue;
        };
        let value = d.value.trim();
        match d.keyword.to_lowercase().as_str() {
            "authenticationmethods" => {
                info.auth_methods = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "passwordauthentication" => {
                info.password_auth = value.eq_ignore_ascii_case("yes");
                seen_password = true;
            }
            "pubkeyauthentication" => {
                info.pubkey_auth = value.eq_ignore_ascii_case("yes");
                seen_pubkey = true;
            }
            "permitrootlogin" => {
                info.permit_root_login = value.to_string();
                seen_permit_root = true;
            }
            _ => {}
        }
    }

    if !seen_pubkey {
        info.pubkey_auth = true;
    }
    if !seen_password {
        info.password_auth = true;
    }
    if !seen_permit_root {
        info.permit_root_login = "prohibit-password".to_string();
    }

    info
}

fn parse_system_users(
    current_ssh_dir: Option<&Path>,
    current_entries: Option<&[AuthorizedKeyEntry]>,
    cache: &SshStateCache,
) -> Vec<SystemUserInfo> {
    if cfg!(target_os = "macos") {
        parse_system_users_macos(current_ssh_dir, current_entries, cache)
    } else {
        parse_system_users_linux(current_ssh_dir, current_entries, cache)
    }
}

fn scan_user_ssh_dir(
    listing: &[(String, Option<FileStamp>)],
    ssh_dir: &std::path::Path,
) -> UserSshScan {
    use crate::ui::screens::ssh::AuthorizedKeyPreview;

    let ssh_key_count = listing.len();

    let Ok(contents) = std::fs::read_to_string(ssh_dir.join("authorized_keys")) else {
        return UserSshScan {
            ssh_key_count,
            authorized_key_count: 0,
            authorized_keys_preview: Vec::new(),
        };
    };

    let mut authorized_key_count = 0usize;
    let mut previews: Vec<AuthorizedKeyPreview> = Vec::new();

    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        authorized_key_count += 1;

        if previews.len() >= USER_PREVIEW_CAP {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let known_types = [
            "ssh-rsa",
            "ssh-dss",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        ];
        let (key_type, base64_idx, comment) =
            if known_types.contains(&tokens[0]) || tokens[0].starts_with("ssh-") {
                (tokens[0], 1, tokens.get(2).copied())
            } else {
                (tokens[1], 2, tokens.get(3).copied())
            };

        let fingerprint = if base64_idx < tokens.len() {
            let openssh = format!("{key_type} {}", tokens[base64_idx]);
            ssh_key::PublicKey::from_openssh(&openssh).ok().map_or_else(
                || "(unknown)".to_string(),
                |k| k.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            )
        } else {
            "(unknown)".to_string()
        };

        previews.push(AuthorizedKeyPreview {
            key_type: key_type.to_string(),
            comment: comment.map(str::to_owned),
            fingerprint,
            line: idx + 1,
        });
    }

    UserSshScan {
        ssh_key_count,
        authorized_key_count,
        authorized_keys_preview: previews,
    }
}

const USER_PREVIEW_CAP: usize = 10;

fn user_scan_from_entries(entries: &[AuthorizedKeyEntry]) -> UserSshScan {
    let previews = entries
        .iter()
        .take(USER_PREVIEW_CAP)
        .map(|e| crate::ui::screens::ssh::AuthorizedKeyPreview {
            key_type: e.key_type.clone(),
            comment: e.comment.clone(),
            fingerprint: e.fingerprint.clone(),
            line: e.line,
        })
        .collect();
    UserSshScan {
        ssh_key_count: 0,
        authorized_key_count: entries.len(),
        authorized_keys_preview: previews,
    }
}

fn user_key_listing(ssh_dir: &std::path::Path) -> Vec<(String, Option<FileStamp>)> {
    let Ok(entries) = std::fs::read_dir(ssh_dir) else {
        return Vec::new();
    };
    let mut listing: Vec<(String, Option<FileStamp>)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("id_")
            || name.ends_with(".pub")
            || name.ends_with(".old")
            || name.ends_with(".bak")
        {
            continue;
        }
        let stamp = stamp_path(&entry.path());
        listing.push((name.into_owned(), stamp));
    }
    listing.sort();
    listing
}

fn scan_user_ssh_cached(
    ssh_dir: &std::path::Path,
    current_ssh_dir: Option<&Path>,
    current_entries: Option<&[AuthorizedKeyEntry]>,
    cache: &SshStateCache,
) -> UserSshScan {
    let listing = user_key_listing(ssh_dir);
    let auth = stamp_path(&ssh_dir.join("authorized_keys"));
    let stamp = UserSshStamp {
        key_listing: listing.clone(),
        auth,
    };

    if current_ssh_dir == Some(ssh_dir)
        && let Some(entries) = current_entries
    {
        let mut scan = user_scan_from_entries(entries);
        scan.ssh_key_count = stamp.key_listing.len();
        return scan;
    }

    if user_scan_cacheable(&stamp) {
        let hit = {
            let scans = cache
                .user_ssh_scans
                .lock()
                .expect("user ssh scan cache mutex poisoned");
            scans
                .get(ssh_dir)
                .filter(|cached| cached.stamp == stamp)
                .map(|cached| Arc::clone(&cached.value))
        };
        if let Some(cached) = hit {
            return (*cached).clone();
        }
    }

    let scan = scan_user_ssh_dir(&listing, ssh_dir);
    if user_scan_cacheable(&stamp) {
        cache
            .user_ssh_scans
            .lock()
            .expect("user ssh scan cache mutex poisoned")
            .insert(
                ssh_dir.to_path_buf(),
                Stamped {
                    stamp,
                    value: Arc::new(scan.clone()),
                },
            );
    }
    scan
}

fn parse_system_users_macos(
    current_ssh_dir: Option<&Path>,
    current_entries: Option<&[AuthorizedKeyEntry]>,
    cache: &SshStateCache,
) -> Vec<SystemUserInfo> {
    let output = match std::process::Command::new("dscl")
        .args([".", "-list", "/Users", "UniqueID"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return vec![],
    };

    let shells = dscl_user_shell_map();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut users = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let username = parts[0];
        let uid: u32 = match parts[1].parse() {
            Ok(u) => u,
            Err(_) => continue,
        };

        if uid < 500 || username.starts_with('_') {
            continue;
        }

        let home_dir = format!("/Users/{username}");
        let home = std::path::Path::new(&home_dir);
        if !home.is_dir() {
            continue;
        }

        let ssh_dir = home.join(".ssh");
        if !ssh_dir.is_dir() {
            continue;
        }

        let shell = shells
            .get(username)
            .cloned()
            .unwrap_or_else(|| "/bin/zsh".to_string());

        let scan = scan_user_ssh_cached(&ssh_dir, current_ssh_dir, current_entries, cache);

        users.push(SystemUserInfo {
            username: username.to_string(),
            shell,
            home_dir,
            ssh_key_count: scan.ssh_key_count,
            authorized_key_count: scan.authorized_key_count,
            authorized_keys_preview: scan.authorized_keys_preview,
        });
    }

    users.sort_by(|a, b| a.username.cmp(&b.username));
    users
}

fn dscl_user_shell_map() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let output = match std::process::Command::new("dscl")
        .args([".", "-list", "/Users", "UserShell"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return map,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(name), Some(shell)) = (parts.next(), parts.next()) {
            map.insert(name.to_string(), shell.to_string());
        }
    }
    map
}

fn parse_system_users_linux(
    current_ssh_dir: Option<&Path>,
    current_entries: Option<&[AuthorizedKeyEntry]>,
    cache: &SshStateCache,
) -> Vec<SystemUserInfo> {
    let Ok(contents) = std::fs::read_to_string("/etc/passwd") else {
        return vec![];
    };

    let invalid_shells = [
        "/bin/false",
        "/sbin/nologin",
        "/usr/sbin/nologin",
        "/bin/nologin",
        "/dev/null",
        "/bin/sync",
        "/usr/bin/nologin",
    ];

    let mut users = Vec::new();

    for line in contents.lines() {
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() < 7 {
            continue;
        }

        let username = parts[0];
        let uid: u32 = match parts[2].parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        let home_dir = parts[5];
        let shell = parts[6];

        if uid < 500 {
            continue;
        }

        if invalid_shells.contains(&shell) || shell.is_empty() {
            continue;
        }

        let home = std::path::Path::new(home_dir);
        if !home.is_dir() {
            continue;
        }

        let ssh_dir = home.join(".ssh");
        if !ssh_dir.is_dir() {
            continue;
        }

        let scan = scan_user_ssh_cached(&ssh_dir, current_ssh_dir, current_entries, cache);

        users.push(SystemUserInfo {
            username: username.to_string(),
            shell: shell.to_string(),
            home_dir: home_dir.to_string(),
            ssh_key_count: scan.ssh_key_count,
            authorized_key_count: scan.authorized_key_count,
            authorized_keys_preview: scan.authorized_keys_preview,
        });
    }

    users.sort_by(|a, b| a.username.cmp(&b.username));
    users
}

#[cfg(test)]
mod mock {
    use super::*;

    pub fn collect_mock_data() -> SshDataBundle {
        SshDataBundle {
            keys: collect_mock_keys(),
            known_hosts: collect_mock_known_hosts(),
            config_hosts: collect_mock_config_hosts(),
            agent_status: collect_mock_agent_status(),
            agent_keys: collect_mock_agent_keys(),
            forwarding: collect_mock_forwarding(),
            diagnostics: Arc::new(collect_mock_diagnostics()),
            authorized_keys: collect_mock_authorized_keys(),
            certificates: collect_mock_certificates(),
            security: collect_mock_security(),
        }
    }

    pub fn collect_mock_keys() -> Vec<SshKeyEntry> {
        vec![
            SshKeyEntry {
                name: "id_ed25519".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:abc123def456ghi789".into(),
                encrypted: true,
                permissions: "0600".into(),
                has_public: true,
                has_cert: false,
                used_by_hosts: vec!["github.com".into(), "gitlab.com".into()],
            },
            SshKeyEntry {
                name: "id_rsa".into(),
                key_type: "RSA 4096".into(),
                fingerprint: "SHA256:xyz789abc456def123".into(),
                encrypted: false,
                permissions: "0644".into(),
                has_public: true,
                has_cert: true,
                used_by_hosts: vec![],
            },
            SshKeyEntry {
                name: "deploy_key".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:qwe456rty789uio012".into(),
                encrypted: false,
                permissions: "0600".into(),
                has_public: true,
                has_cert: false,
                used_by_hosts: vec![
                    "prod-server".into(),
                    "staging".into(),
                    "dev".into(),
                    "backup".into(),
                    "monitor".into(),
                ],
            },
        ]
    }

    pub fn collect_mock_known_hosts() -> Vec<KnownHostEntry> {
        vec![
            KnownHostEntry {
                hosts: vec!["github.com".into()],
                key_type: "ssh-ed25519".into(),
                key_types: vec![
                    "ssh-ed25519".into(),
                    "ecdsa-sha2-nistp256".into(),
                    "ssh-rsa".into(),
                ],
                fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".into(),
                fingerprints: vec![
                    "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".into(),
                    "SHA256:p2QDBXBNJXm3QqRJLcYPjMn+al+gPCfvAy8Oo5WKIqs".into(),
                    "SHA256:uNiVztksCsDhccIuweeDlI0Q5J0q+Z7RDwt5kM+VmEc".into(),
                ],
                is_hashed: false,
                marker: None,
                comment: None,
                line: 1,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["gitlab.com".into()],
                key_type: "ssh-ed25519".into(),
                key_types: vec!["ssh-ed25519".into()],
                fingerprint: "SHA256:WSCtr3bEeJGgcb0UrkMFWxQJqchWXzwWMNESdgqxo".into(),
                fingerprints: vec!["SHA256:WSCtr3bEeJGgcb0UrkMFWxQJqchWXzwWMNESdgqxo".into()],
                is_hashed: false,
                marker: None,
                comment: None,
                line: 2,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["[192.168.1.1]:2222".into()],
                key_type: "ssh-rsa".into(),
                key_types: vec!["ssh-rsa".into()],
                fingerprint: "SHA256:abc123def456ghi789jkl012mno345pqr678".into(),
                fingerprints: vec!["SHA256:abc123def456ghi789jkl012mno345pqr678".into()],
                is_hashed: false,
                marker: None,
                comment: Some("home router".into()),
                line: 3,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["|1|ba4dEeFgHiJkLmNoPqRsTu|XxYyZz0123456789".into()],
                key_type: "ecdsa-sha2-nistp256".into(),
                key_types: vec!["ecdsa-sha2-nistp256".into()],
                fingerprint: "SHA256:qwe456rty789uio012pqr345stu678vwx".into(),
                fingerprints: vec!["SHA256:qwe456rty789uio012pqr345stu678vwx".into()],
                is_hashed: true,
                marker: None,
                comment: None,
                line: 4,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["old.server.example.com".into()],
                key_type: "ssh-ed25519".into(),
                key_types: vec!["ssh-ed25519".into()],
                fingerprint: "SHA256:xyz789abc456def123ghi456jkl789mno012".into(),
                fingerprints: vec!["SHA256:xyz789abc456def123ghi456jkl789mno012".into()],
                is_hashed: false,
                marker: Some("@revoked".into()),
                comment: None,
                line: 5,
                source: "user".into(),
            },
        ]
    }

    pub fn collect_mock_config_hosts() -> Vec<ConfigHostEntry> {
        vec![
            ConfigHostEntry {
                name: "myserver".into(),
                patterns: vec!["myserver".into()],
                host_name: Some("example.com".into()),
                user: Some("alice".into()),
                port: Some(2222),
                identity_file: Some("~/.ssh/id_ed25519".into()),
                proxy_jump: None,
                directive_count: 5,
                has_diagnostic: false,
            },
            ConfigHostEntry {
                name: "*.example.com".into(),
                patterns: vec!["*.example.com".into()],
                host_name: None,
                user: Some("deploy".into()),
                port: None,
                identity_file: None,
                proxy_jump: None,
                directive_count: 3,
                has_diagnostic: false,
            },
            ConfigHostEntry {
                name: "*".into(),
                patterns: vec!["*".into()],
                host_name: None,
                user: None,
                port: None,
                identity_file: None,
                proxy_jump: None,
                directive_count: 2,
                has_diagnostic: false,
            },
            ConfigHostEntry {
                name: "staging".into(),
                patterns: vec!["staging".into()],
                host_name: Some("stage.example.com".into()),
                user: Some("bob".into()),
                port: Some(22),
                identity_file: Some("~/.ssh/deploy_key".into()),
                proxy_jump: Some("bastion.example.com".into()),
                directive_count: 8,
                has_diagnostic: true,
            },
            ConfigHostEntry {
                name: "bastion".into(),
                patterns: vec!["bastion.example.com".into()],
                host_name: None,
                user: Some("admin".into()),
                port: Some(443),
                identity_file: Some("~/.ssh/id_ed25519".into()),
                proxy_jump: None,
                directive_count: 4,
                has_diagnostic: false,
            },
        ]
    }

    pub fn collect_mock_agent_status() -> AgentStatus {
        AgentStatus {
            reachable: true,
            socket_path: Some("/tmp/ssh-abc123/agent.1234".into()),
            key_count: 3,
        }
    }

    pub fn collect_mock_agent_keys() -> Vec<AgentKeyEntry> {
        vec![
            AgentKeyEntry {
                name: "id_ed25519".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:abc123def456ghi789".into(),
                is_locked: false,
                has_constraints: false,
            },
            AgentKeyEntry {
                name: "deploy_key".into(),
                key_type: "RSA 4096".into(),
                fingerprint: "SHA256:xyz789abc456def123".into(),
                is_locked: true,
                has_constraints: true,
            },
            AgentKeyEntry {
                name: "staging_key".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:qwe456rty789uio012".into(),
                is_locked: false,
                has_constraints: false,
            },
        ]
    }

    pub fn collect_mock_forwarding() -> Vec<ForwardSessionEntry> {
        vec![
            ForwardSessionEntry {
                host: "myserver".into(),
                control_path: "/home/alice/.ssh/cm-alice@example.com:22".into(),
                pid: Some(1234),
                established_ago: "2h 15m".into(),
                forward_count: 2,
                forwards: vec![
                    ForwardEntry {
                        forward_type: "local".into(),
                        local_addr: "127.0.0.1".into(),
                        local_port: 8080,
                        remote_addr: "example.com".into(),
                        remote_port: 80,
                    },
                    ForwardEntry {
                        forward_type: "local".into(),
                        local_addr: "127.0.0.1".into(),
                        local_port: 3306,
                        remote_addr: "db.example.com".into(),
                        remote_port: 3306,
                    },
                ],
            },
            ForwardSessionEntry {
                host: "bastion".into(),
                control_path: "/home/alice/.ssh/ctrl-bastion".into(),
                pid: Some(5678),
                established_ago: "45m".into(),
                forward_count: 2,
                forwards: vec![
                    ForwardEntry {
                        forward_type: "dynamic".into(),
                        local_addr: "127.0.0.1".into(),
                        local_port: 1080,
                        remote_addr: "SOCKS".into(),
                        remote_port: 0,
                    },
                    ForwardEntry {
                        forward_type: "remote".into(),
                        local_addr: "0.0.0.0".into(),
                        local_port: 2222,
                        remote_addr: "127.0.0.1".into(),
                        remote_port: 22,
                    },
                ],
            },
        ]
    }

    pub fn collect_mock_diagnostics() -> Vec<DiagnosticEntry> {
        vec![
            DiagnosticEntry {
                id: "ssh_dir_exists".into(),
                severity: "ok".into(),
                module: "local".into(),
                message: "SSH directory exists with correct permissions (0700)".into(),
                hint: None,
            },
            DiagnosticEntry {
                id: "config_found".into(),
                severity: "info".into(),
                module: "config".into(),
                message: "SSH config file found at ~/.ssh/config".into(),
                hint: None,
            },
            DiagnosticEntry {
                id: "key_permissions".into(),
                severity: "warning".into(),
                module: "local".into(),
                message: "Private key id_rsa has overly permissive mode (0644)".into(),
                hint: Some("Run chmod 600 ~/.ssh/id_rsa to fix".into()),
            },
            DiagnosticEntry {
                id: "agent_not_running".into(),
                severity: "error".into(),
                module: "agent".into(),
                message: "No SSH agent is running (SSH_AUTH_SOCK not set)".into(),
                hint: Some("Start ssh-agent or add eval $(ssh-agent) to your shell profile".into()),
            },
            DiagnosticEntry {
                id: "config_host_star_placement".into(),
                severity: "warning".into(),
                module: "config".into(),
                message: "'Host *' appears before specific Host blocks".into(),
                hint: Some("Move 'Host *' to the end of the config file".into()),
            },
            DiagnosticEntry {
                id: "known_hosts_exists".into(),
                severity: "ok".into(),
                module: "local".into(),
                message: "Known hosts file exists at ~/.ssh/known_hosts".into(),
                hint: None,
            },
        ]
    }

    pub fn collect_mock_authorized_keys() -> Vec<AuthorizedKeyEntry> {
        vec![
            AuthorizedKeyEntry {
                key_type: "ssh-ed25519".into(),
                public_key: "AAAAC3NzaC1lZDI1NTE5AAAAIKxJ3G2F7mT5mQaV8eN4pL2zH8gR6kW".into(),
                comment: Some("alice@workstation".into()),
                fingerprint: "SHA256:xKj8mN2pL5vR7tQ9wE3yU4oI6aS8dF".into(),
                options: None,
                line: 1,
            },
            AuthorizedKeyEntry {
                key_type: "ssh-rsa".into(),
                public_key: "AAAAB3NzaC1yc2EAAAADAQABAAACAQCr7L3hFS2jW9eJ5kE8mN".into(),
                comment: Some("deploy@ci-runner".into()),
                fingerprint: "SHA256:mQ9wE3yU4oI6aS8dFxKj8mN2pL5vR7t".into(),
                options: Some("command=\"/usr/bin/restricted-shell\",no-port-forwarding".into()),
                line: 4,
            },
            AuthorizedKeyEntry {
                key_type: "ssh-ed25519".into(),
                public_key: "AAAAC3NzaC1lZDI1NTE5AAAAIP9fG4eJ8kL3mN6oQ2rS5tU7vW".into(),
                comment: Some("bob@laptop".into()),
                fingerprint: "SHA256:R7tQ9wE3yU4oI6aS8dFxKj8mN2pL5v".into(),
                options: None,
                line: 7,
            },
            AuthorizedKeyEntry {
                key_type: "ecdsa-sha2-nistp256".into(),
                public_key: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY".into(),
                comment: None,
                fingerprint: "SHA256:U4oI6aS8dFxKj8mN2pL5vR7tQ9wE3y".into(),
                options: Some("no-pty".into()),
                line: 9,
            },
        ]
    }

    pub fn collect_mock_certificates() -> Vec<CertificateEntry> {
        vec![
            CertificateEntry {
                name: "id_ed25519-cert.pub".into(),
                cert_type: "User".into(),
                key_type: "ssh-ed25519-cert-v01@openssh.com".into(),
                serial: 12345,
                valid_from: "2025-01-15 00:00:00".into(),
                valid_to: "2026-01-15 00:00:00".into(),
                is_valid: true,
                ca_fingerprint: "SHA256:CA1fP2gH3iJ4kL5mN6oQ7rS8tU".into(),
                key_id: "alice@corp-2025".into(),
                principals: vec!["alice".into(), "admin".into()],
            },
            CertificateEntry {
                name: "deploy-cert.pub".into(),
                cert_type: "User".into(),
                key_type: "ssh-ed25519-cert-v01@openssh.com".into(),
                serial: 67890,
                valid_from: "2024-06-01 00:00:00".into(),
                valid_to: "2025-06-01 00:00:00".into(),
                is_valid: false,
                ca_fingerprint: "SHA256:CA9qR8sT7uV6wX5yZ4aB3cD2eF".into(),
                key_id: "deploy@ci-2024".into(),
                principals: vec!["deploy".into()],
            },
            CertificateEntry {
                name: "bastion-host-cert.pub".into(),
                cert_type: "Host".into(),
                key_type: "ssh-rsa-cert-v01@openssh.com".into(),
                serial: 42,
                valid_from: "2025-03-01 00:00:00".into(),
                valid_to: "2026-03-01 00:00:00".into(),
                is_valid: true,
                ca_fingerprint: "SHA256:CA2gH3iJ4kL5mN6oP7qR8sT9uV".into(),
                key_id: "bastion.example.com".into(),
                principals: vec!["bastion.example.com".into()],
            },
        ]
    }

    pub fn collect_mock_security() -> SshSecurityData {
        let mut sshd_config = HashMap::new();
        sshd_config.insert("passwordauthentication".into(), "no".into());
        sshd_config.insert("permitrootlogin".into(), "prohibit-password".into());
        sshd_config.insert("port".into(), "22".into());
        sshd_config.insert("pubkeyauthentication".into(), "yes".into());
        sshd_config.insert("maxauthtries".into(), "3".into());
        sshd_config.insert("allowagentforwarding".into(), "no".into());
        sshd_config.insert("x11forwarding".into(), "no".into());
        sshd_config.insert("permitemptypasswords".into(), "no".into());

        SshSecurityData {
            sshd_config,
            authorized_key_count: 4,
            authorized_key_labels: vec![
                "alice@workstation".into(),
                "deploy@ci-runner".into(),
                "bob@laptop".into(),
                "(no comment)".into(),
            ],
            known_hosts_count: 5,
            known_hosts_hashed_count: 1,
            security_diagnostics: vec![DiagnosticEntry {
                id: "key_permissions".into(),
                severity: "warning".into(),
                module: "local".into(),
                message: "Private key id_rsa has overly permissive mode (0644)".into(),
                hint: Some("Run chmod 600 ~/.ssh/id_rsa".into()),
            }],
            access_info: SshAccessInfo {
                available: true,
                allowed_users: vec![],
                denied_users: vec![],
                allowed_groups: vec!["ssh-users".into()],
                denied_groups: vec![],
                auth_methods: vec!["publickey".into()],
                password_auth: false,
                pubkey_auth: true,
                permit_root_login: "prohibit-password".into(),
            },
            system_users: vec![
                SystemUserInfo {
                    username: "alice".into(),
                    shell: "/bin/bash".into(),
                    home_dir: "/home/alice".into(),
                    ssh_key_count: 2,
                    authorized_key_count: 3,
                    authorized_keys_preview: Vec::new(),
                },
                SystemUserInfo {
                    username: "bob".into(),
                    shell: "/bin/zsh".into(),
                    home_dir: "/home/bob".into(),
                    ssh_key_count: 1,
                    authorized_key_count: 1,
                    authorized_keys_preview: Vec::new(),
                },
                SystemUserInfo {
                    username: "root".into(),
                    shell: "/bin/bash".into(),
                    home_dir: "/root".into(),
                    ssh_key_count: 0,
                    authorized_key_count: 0,
                    authorized_keys_preview: Vec::new(),
                },
            ],
            is_root: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCRYPTED_ED25519_PEM: &str = r"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCCl+BJeR
6fh9cjkIDA+Xy9AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILgUYeqGhLirfiaY
jS17uJqeK1rdQxFmtieIPp+gBl1QAAAAkPTsdRb/dX+52v+LSgi2fzPxv2q2iJd8uKr2Ee
5eyX2qFxQoysBDn8fRRsmqT+9RevfJU+dtl9D31ObAi0ZNMvkFzddgriQLxhb5MJopDN48
7gYRaguTorV6QQxtv2e/TUluUVUHxMZPe1c3De0Tslxhs1LNvsNWDFNLPw3QAZ5wPYUXEc
7jKXjoSvb0HXE1ZA==
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn keygen_read_public_argv_omits_passphrase_flag() {
        let argv = keygen_read_public_argv("/home/u/.ssh/id_ed25519");
        assert_eq!(argv.len(), 3, "expected [-y, -f, <key>]: {argv:?}");
        assert_eq!(argv[0], "-y");
        assert_eq!(argv[1], "-f");
        assert_eq!(argv[2], "/home/u/.ssh/id_ed25519");
        assert!(
            !argv.iter().any(|a| a == "-P" || a == "-N"),
            "passphrase must never appear on the ssh-keygen argv: {argv:?}"
        );
    }

    #[test]
    fn check_key_passphrase_uses_askpass_not_argv() {
        let probe = std::process::Command::new("ssh-keygen")
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if probe.is_err() {
            eprintln!("ssh-keygen not on PATH; skipping askpass integration test");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("enc_ed25519");
        std::fs::write(&key, ENCRYPTED_ED25519_PEM).expect("write fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 0600");
        }
        assert!(
            check_key_passphrase(&key, "toride-test-passphrase").unwrap(),
            "correct passphrase should verify"
        );
        assert!(
            !check_key_passphrase(&key, "definitely-wrong").unwrap(),
            "wrong passphrase should be rejected"
        );
    }

    fn grade_score(g: SecurityGrade) -> u8 {
        match g {
            SecurityGrade::A => 5,
            SecurityGrade::B => 4,
            SecurityGrade::C => 3,
            SecurityGrade::D => 2,
            SecurityGrade::F => 1,
        }
    }

    #[test]
    fn new_is_not_pending() {
        let collector = SshDataCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            SshDataCollector::new().is_pending(),
            SshDataCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = SshDataCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = SshDataCollector::new();
        collector.start();
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = SshDataCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let result = collector.poll().await;
        assert!(result.is_some());
        let bundle = result.unwrap();
        assert!(
            bundle.security.access_info.pubkey_auth,
            "pubkey_auth should default to true"
        );
        assert!(
            !bundle.security.access_info.permit_root_login.is_empty(),
            "permit_root_login should have a default value"
        );
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = SshDataCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = SshDataCollector::new();
        let result = collector.poll().await;
        assert!(result.is_none());
    }

    #[test]
    fn mock_data_have_expected_content() {
        let bundle = mock::collect_mock_data();
        assert!(!bundle.keys.is_empty());
        assert!(!bundle.known_hosts.is_empty());
        assert!(!bundle.config_hosts.is_empty());
        assert!(!bundle.agent_keys.is_empty());
        assert!(!bundle.forwarding.is_empty());
        assert!(!bundle.diagnostics.is_empty());
        assert!(!bundle.authorized_keys.is_empty());
        assert!(!bundle.certificates.is_empty());
        assert!(bundle.agent_status.reachable);
        assert!(bundle.security.authorized_key_count > 0);
        assert!(!bundle.security.sshd_config.is_empty());
        assert_eq!(bundle.security.checks().len(), 8);
    }

    #[test]
    fn security_grade_a_when_secure() {
        let security = mock::collect_mock_security();
        assert_eq!(security.grade(), SecurityGrade::A);
    }

    #[test]
    fn security_grade_d_when_mostly_insecure() {
        let mut security = mock::collect_mock_security();
        security
            .sshd_config
            .insert("passwordauthentication".into(), "yes".into());
        security
            .sshd_config
            .insert("permitrootlogin".into(), "yes".into());
        assert_eq!(security.grade(), SecurityGrade::D);
    }

    #[test]
    fn security_grade_f_when_fully_insecure() {
        let mut security = mock::collect_mock_security();
        security
            .sshd_config
            .insert("passwordauthentication".into(), "yes".into());
        security
            .sshd_config
            .insert("permitrootlogin".into(), "yes".into());
        security
            .sshd_config
            .insert("permitemptypasswords".into(), "yes".into());
        security
            .sshd_config
            .insert("pubkeyauthentication".into(), "no".into());
        assert_eq!(security.grade(), SecurityGrade::F);
    }

    #[test]
    fn security_grade_b_with_password_auth() {
        let mut security = mock::collect_mock_security();
        security.security_diagnostics = vec![];
        security
            .sshd_config
            .insert("passwordauthentication".into(), "yes".into());
        assert_eq!(security.grade(), SecurityGrade::B);
    }

    #[test]
    fn security_grade_c_with_password_and_root_login() {
        let mut security = mock::collect_mock_security();
        security.security_diagnostics = vec![];
        security
            .sshd_config
            .insert("passwordauthentication".into(), "yes".into());
        security
            .sshd_config
            .insert("permitrootlogin".into(), "yes".into());
        assert_eq!(security.grade(), SecurityGrade::C);
    }

    #[test]
    fn sshd_bool_parses_yes_no_true_false_one_zero_case_insensitively() {
        for yes in &["yes", "Yes", "YES", "yEs", "true", "True", "TRUE", "1"] {
            assert_eq!(sshd_bool(yes), Some(true), "{yes:?} must be true");
        }
        for no in &["no", "No", "NO", "nO", "false", "False", "FALSE", "0"] {
            assert_eq!(sshd_bool(no), Some(false), "{no:?} must be false");
        }
        assert_eq!(sshd_bool("  yes  "), Some(true));
        assert_eq!(sshd_bool("  no\t"), Some(false));
        assert_eq!(sshd_bool("prohibit-password"), None);
        assert_eq!(sshd_bool(""), None);
        assert_eq!(sshd_bool("random"), None);
    }

    #[test]
    fn grade_deducts_root_login_for_capitalized_yes() {
        let mut lower = mock::collect_mock_security();
        lower.security_diagnostics = vec![];
        lower
            .sshd_config
            .insert("permitrootlogin".into(), "yes".into());

        let mut upper = mock::collect_mock_security();
        upper.security_diagnostics = vec![];
        upper
            .sshd_config
            .insert("permitrootlogin".into(), "Yes".into());

        assert_eq!(
            lower.grade(),
            upper.grade(),
            "capitalized 'Yes' must grade identically to lowercase 'yes'"
        );
        let secure = mock::collect_mock_security();
        assert!(
            grade_score(upper.grade()) < grade_score(secure.grade()),
            "PermitRootLogin Yes must deduct points (regression: was silently passing)"
        );
    }

    #[test]
    fn grade_treats_all_capitalizations_consistently() {
        let mk = |pw: &str, root: &str, empty: &str, pubkey: &str| {
            let mut s = mock::collect_mock_security();
            s.security_diagnostics = vec![];
            s.sshd_config
                .insert("passwordauthentication".into(), pw.into());
            s.sshd_config.insert("permitrootlogin".into(), root.into());
            s.sshd_config
                .insert("permitemptypasswords".into(), empty.into());
            s.sshd_config
                .insert("pubkeyauthentication".into(), pubkey.into());
            s
        };
        let lower = mk("yes", "yes", "yes", "no");
        let upper = mk("YES", "YES", "YES", "NO");
        let mixed = mk("Yes", "Yes", "Yes", "No");
        assert_eq!(lower.grade(), upper.grade());
        assert_eq!(lower.grade(), mixed.grade());
    }

    #[test]
    fn checks_capitalized_yes_is_flagged_insecure() {
        let mut security = mock::collect_mock_security();
        security
            .sshd_config
            .insert("permitrootlogin".into(), "Yes".into());

        let root_check = security
            .checks()
            .into_iter()
            .find(|c| c.label == "Root login")
            .expect("root login check exists");
        assert!(
            !root_check.passing,
            "PermitRootLogin Yes must NOT be passing (regression: was passing)"
        );
        assert_eq!(root_check.detail, "Yes");
    }

    #[test]
    fn checks_pubkey_no_capitalized_is_flagged() {
        let mut security = mock::collect_mock_security();
        security
            .sshd_config
            .insert("pubkeyauthentication".into(), "NO".into());

        let pubkey_check = security
            .checks()
            .into_iter()
            .find(|c| c.label == "Public key auth")
            .expect("pubkey check exists");
        assert!(
            !pubkey_check.passing,
            "PubkeyAuthentication NO must NOT be passing (regression: was passing)"
        );
    }

    #[test]
    fn checks_password_authentication_no_capitalized_is_passing() {
        let mut security = mock::collect_mock_security();
        security
            .sshd_config
            .insert("passwordauthentication".into(), "No".into());

        let pw_check = security
            .checks()
            .into_iter()
            .find(|c| c.label == "Password authentication")
            .expect("password check exists");
        assert!(
            pw_check.passing,
            "PasswordAuthentication No (capitalized) must be passing"
        );
    }

    #[test]
    fn parse_sshd_config_from_empty() {
        let config = parse_sshd_config_from("");
        assert!(config.is_empty());
    }

    #[test]
    fn parse_sshd_config_from_skips_comments() {
        let contents = "# this is a comment\nPort 2222\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
        assert_eq!(config.len(), 1);
    }

    #[test]
    fn parse_sshd_config_from_skips_empty_lines() {
        let contents = "\n\nPort 2222\n\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
    }

    #[test]
    fn parse_sshd_config_from_skips_match_blocks() {
        let contents =
            "Port 2222\nMatch Address 192.168.0.0/16\nInclude /nonexistent/nowhere/*.conf\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
        assert!(
            !config.contains_key("match address 192.168.0.0/16"),
            "Match header must not leak as a key"
        );
        assert!(
            !config.contains_key("include"),
            "Include directive must not become a map key"
        );
        assert_eq!(config.len(), 1, "only the global Port directive expected");
    }

    #[test]
    fn parse_sshd_config_from_expands_include_relative_to_base_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dropdir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropdir).expect("mkdir dropin");
        std::fs::write(dropdir.join("50-hardening.conf"), "PermitRootLogin no\n")
            .expect("write dropin");

        let main = "Include sshd_config.d/*.conf\n";
        let config = parse_sshd_config_from_dir(main, dir.path());
        assert_eq!(
            config.get("permitrootlogin"),
            Some(&"no".to_string()),
            "drop-in must be merged so grading sees the effective value"
        );
    }

    #[test]
    fn parse_sshd_config_from_include_first_occurrence_wins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dropdir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropdir).expect("mkdir dropin");
        std::fs::write(dropdir.join("99-override.conf"), "PermitRootLogin yes\n")
            .expect("write dropin");

        let main = "PermitRootLogin no\nInclude sshd_config.d/*.conf\n";
        let config = parse_sshd_config_from_dir(main, dir.path());
        assert_eq!(
            config.get("permitrootlogin"),
            Some(&"no".to_string()),
            "first-occurrence-wins: main file directive must beat the drop-in"
        );
    }

    #[test]
    fn parse_sshd_config_from_include_absolute_pattern() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("custom.conf");
        std::fs::write(&target, "PasswordAuthentication no\n").expect("write");

        let main = format!("Include {}\n", target.display());
        let config = parse_sshd_config_from_dir(&main, Path::new("/etc/ssh"));
        assert_eq!(
            config.get("passwordauthentication"),
            Some(&"no".to_string()),
            "absolute Include must be followed"
        );
    }

    #[test]
    fn parse_sshd_config_from_production_entry_expands_absolute_include() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("dropin.conf");
        std::fs::write(&target, "PermitRootLogin no\n").expect("write dropin");

        let main = format!("Include {}\n", target.display());
        let config = parse_sshd_config_from(&main);
        assert_eq!(
            config.get("permitrootlogin"),
            Some(&"no".to_string()),
            "production entry must expand the absolute Include"
        );
    }

    #[test]
    fn parse_sshd_config_from_include_sorted_glob_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dropdir = dir.path().join("sshd_config.d");
        std::fs::create_dir_all(&dropdir).expect("mkdir dropin");
        std::fs::write(dropdir.join("10-a.conf"), "Port 1000\n").expect("write a");
        std::fs::write(dropdir.join("20-b.conf"), "Port 2000\n").expect("write b");

        let main = "Include sshd_config.d/*.conf\n";
        let config = parse_sshd_config_from_dir(main, dir.path());
        assert_eq!(
            config.get("port"),
            Some(&"1000".to_string()),
            "sorted glob: 10-a.conf (first) must win over 20-b.conf"
        );
    }

    #[test]
    fn parse_sshd_config_from_include_cycle_safe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("loopy.conf");
        let body = format!("Port 9999\nInclude {}\n", target.display());
        std::fs::write(&target, &body).expect("write");

        let main = format!("Include {}\n", target.display());
        let config = parse_sshd_config_from_dir(&main, dir.path());
        assert_eq!(
            config.get("port"),
            Some(&"9999".to_string()),
            "cycle guard must still parse the directive once"
        );
    }

    #[test]
    fn parse_sshd_config_from_keys_are_lowercased() {
        let contents = "PasswordAuthentication no\nPermitRootLogin yes\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(
            config.get("passwordauthentication"),
            Some(&"no".to_string())
        );
        assert_eq!(config.get("permitrootlogin"), Some(&"yes".to_string()));
    }

    #[test]
    fn parse_sshd_config_from_various_whitespace() {
        let contents = "Port 2222\nMaxAuthTries 3\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
        assert_eq!(config.get("maxauthtries"), Some(&"3".to_string()));
    }

    #[test]
    fn parse_access_info_defaults_when_empty() {
        let info = parse_sshd_access_info_from("");
        assert!(info.pubkey_auth, "pubkey_auth should default to true");
        assert!(info.password_auth, "password_auth should default to true");
        assert_eq!(info.permit_root_login, "prohibit-password");
        assert!(info.allowed_users.is_empty());
        assert!(info.denied_users.is_empty());
    }

    #[test]
    fn parse_access_info_explicit_values() {
        let contents = "\
            PasswordAuthentication no\n\
            PubkeyAuthentication yes\n\
            PermitRootLogin no\n\
            AllowUsers alice bob\n\
            DenyUsers guest\n\
            AllowGroups ssh-users\n\
            DenyGroups no-ssh\n\
            AuthenticationMethods publickey,keyboard-interactive\n";
        let info = parse_sshd_access_info_from(contents);
        assert!(!info.password_auth);
        assert!(info.pubkey_auth);
        assert_eq!(info.permit_root_login, "no");
        assert_eq!(info.allowed_users, vec!["alice", "bob"]);
        assert_eq!(info.denied_users, vec!["guest"]);
        assert_eq!(info.allowed_groups, vec!["ssh-users"]);
        assert_eq!(info.denied_groups, vec!["no-ssh"]);
        assert_eq!(info.auth_methods, vec!["publickey", "keyboard-interactive"]);
    }

    #[test]
    fn parse_access_info_pubkey_no_is_preserved() {
        let contents = "PubkeyAuthentication no\n";
        let info = parse_sshd_access_info_from(contents);
        assert!(!info.pubkey_auth, "explicit 'no' should be preserved");
    }

    #[test]
    fn parse_access_info_password_no_is_preserved() {
        let contents = "PasswordAuthentication no\n";
        let info = parse_sshd_access_info_from(contents);
        assert!(!info.password_auth, "explicit 'no' should be preserved");
    }

    #[test]
    fn parse_access_info_skips_match_scoped_directives() {
        let contents = concat!(
            "PasswordAuthentication no\n",
            "Match Address 192.168.0.0/16\n",
            "    PasswordAuthentication yes\n",
        );
        let info = parse_sshd_access_info_from(contents);
        assert!(
            !info.password_auth,
            "global PasswordAuthentication=no must win over Match-scoped yes"
        );
    }

    #[test]
    fn parse_access_info_match_scoped_allow_users_does_not_leak() {
        let contents = concat!(
            "AllowUsers alice\n",
            "Match User carol\n",
            "    AllowUsers bob\n",
        );
        let info = parse_sshd_access_info_from(contents);
        assert_eq!(
            info.allowed_users,
            vec!["alice"],
            "Match-scoped AllowUsers must not leak into the global list"
        );
        assert!(
            !info.allowed_users.contains(&"bob".to_string()),
            "Match-scoped user 'bob' leaked into global allowed_users"
        );
    }

    #[test]
    fn parse_access_info_concatenates_multiple_global_allow_users() {
        let contents = concat!("AllowUsers alice\n", "Port 22\n", "AllowUsers bob carol\n",);
        let info = parse_sshd_access_info_from(contents);
        assert_eq!(
            info.allowed_users,
            vec!["alice", "bob", "carol"],
            "multiple global AllowUsers lines must concatenate in order"
        );

        let contents = concat!(
            "DenyUsers dan\n",
            "DenyUsers eve\n",
            "AllowGroups wheel\n",
            "AllowGroups staff\n",
            "DenyGroups banned\n",
            "DenyGroups revoked\n",
        );
        let info = parse_sshd_access_info_from(contents);
        assert_eq!(info.denied_users, vec!["dan", "eve"]);
        assert_eq!(info.allowed_groups, vec!["wheel", "staff"]);
        assert_eq!(info.denied_groups, vec!["banned", "revoked"]);
    }

    #[test]
    fn parse_access_info_read_matches_editor_getters() {
        use toride_ssh::config::ast::parse;
        use toride_ssh::config::sshd::{
            get_allow_groups, get_allow_users, get_deny_groups, get_deny_users,
        };

        let contents = concat!(
            "AllowUsers alice\n",
            "DenyUsers mallory\n",
            "AllowGroups wheel\n",
            "DenyGroups banned\n",
            "Match User carol\n",
            "    AllowUsers bob\n",
            "    DenyUsers scoped\n",
        );
        let info = parse_sshd_access_info_from(contents);

        let ast = parse(contents);
        assert_eq!(info.allowed_users, get_allow_users(&ast));
        assert_eq!(info.denied_users, get_deny_users(&ast));
        assert_eq!(info.allowed_groups, get_allow_groups(&ast));
        assert_eq!(info.denied_groups, get_deny_groups(&ast));
        assert_eq!(info.allowed_users, vec!["alice"]);
        assert_eq!(info.denied_users, vec!["mallory"]);
    }

    use tokio::sync::Mutex;
    static HOME_LOCK: Mutex<usize> = Mutex::const_new(0);

    async fn acquire_home_lock() -> tokio::sync::MutexGuard<'static, usize> {
        HOME_LOCK.lock().await
    }

    struct TempHome {
        original: Option<std::path::PathBuf>,
        _dir: tempfile::TempDir,
    }

    impl TempHome {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let ssh_dir = dir.path().join(".ssh");
            std::fs::create_dir_all(&ssh_dir).expect("mkdir .ssh");
            let original = std::env::var_os("HOME").map(std::path::PathBuf::from);
            // SAFETY: test-only; HOME_LOCK ensures serial execution.
            unsafe {
                std::env::set_var("HOME", dir.path());
            }
            Self {
                original,
                _dir: dir,
            }
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            // SAFETY: test-only; restoring original state.
            unsafe {
                if let Some(ref orig) = self.original {
                    std::env::set_var("HOME", orig);
                } else {
                    std::env::remove_var("HOME");
                }
            }
        }
    }

    #[tokio::test]
    async fn execute_op_config_add_host_writes_to_disk() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let op = SshOp::ConfigAddHost {
            name: "test-toride-host".into(),
            host_name: Some("192.168.1.99".into()),
            user: Some("testuser".into()),
            port: Some(2222),
        };
        let result = execute_op(op).await;
        assert!(result.is_ok(), "config add failed: {:?}", result.err());
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ast = mgr.config().load().await.expect("load");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("test-toride-host"),
            "host not in config: {content}"
        );
        let op2 = SshOp::ConfigRemoveHost {
            name: "test-toride-host".into(),
        };
        let result2 = execute_op(op2).await;
        assert!(result2.is_ok(), "config remove failed: {:?}", result2.err());
    }

    #[tokio::test]
    async fn execute_op_config_add_duplicate_fails() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let op = SshOp::ConfigAddHost {
            name: "dupe-host".into(),
            host_name: None,
            user: None,
            port: None,
        };
        assert!(execute_op(op).await.is_ok());
        let op2 = SshOp::ConfigAddHost {
            name: "dupe-host".into(),
            host_name: None,
            user: None,
            port: None,
        };
        let result = execute_op(op2).await;
        assert!(result.is_err(), "duplicate add should fail: {result:?}");
    }

    #[tokio::test]
    async fn execute_op_config_remove_nonexistent_fails() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let op = SshOp::ConfigRemoveHost {
            name: "no-such-host".into(),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_err(),
            "removing nonexistent host should fail: {result:?}"
        );
    }

    #[tokio::test]
    async fn execute_op_config_edit_host_replaces() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let op = SshOp::ConfigAddHost {
            name: "edit-me".into(),
            host_name: Some("old.example.com".into()),
            user: Some("olduser".into()),
            port: Some(22),
        };
        assert!(execute_op(op).await.is_ok());
        let op2 = SshOp::ConfigEditHost {
            old_name: "edit-me".into(),
            new_name: "edit-me".into(),
            host_name: Some("new.example.com".into()),
            user: Some("newuser".into()),
            port: Some(443),
        };
        let result = execute_op(op2).await;
        assert!(result.is_ok(), "config edit failed: {:?}", result.err());
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ast = mgr.config().load().await.expect("load");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("new.example.com"),
            "new hostname in config: {content}"
        );
        assert!(
            !content.contains("old.example.com"),
            "old hostname gone: {content}"
        );
    }

    #[tokio::test]
    async fn execute_op_key_create_and_delete() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let op = SshOp::KeyCreate {
            name: "toride-test-key".into(),
            key_type: "Ed25519".into(),
            comment: "test@toride".into(),
            passphrase: None,
        };
        let result = execute_op(op).await;
        assert!(result.is_ok(), "key create failed: {:?}", result.err());
        let home = std::env::var("HOME").expect("HOME");
        let key_path = std::path::Path::new(&home).join(".ssh/toride-test-key");
        assert!(
            key_path.exists(),
            "private key file should exist at {}",
            key_path.display()
        );
        let op2 = SshOp::KeyDelete {
            name: "toride-test-key".into(),
        };
        let result2 = execute_op(op2).await;
        assert!(result2.is_ok(), "key delete failed: {:?}", result2.err());
        assert!(!key_path.exists(), "key file should be deleted");
    }

    #[tokio::test]
    async fn key_full_crud_lifecycle() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let home = std::env::var("HOME").expect("HOME");

        let params = toride_ssh::KeyCreateParams::ed25519("id_crud_test_key".to_owned());
        mgr.keys()
            .create(params)
            .await
            .expect("Step 1 CREATE: key generation failed");
        eprintln!("✓ Step 1: CREATE key 'id_crud_test_key'");

        let private = std::path::Path::new(&home).join(".ssh/id_crud_test_key");
        let public = std::path::Path::new(&home).join(".ssh/id_crud_test_key.pub");
        assert!(
            private.exists(),
            "Step 2 VERIFY: private key missing at {private:?}"
        );
        assert!(
            public.exists(),
            "Step 2 VERIFY: public key missing at {public:?}"
        );
        eprintln!("✓ Step 2: VERIFY files exist");

        let keys = mgr.keys().list().await.expect("Step 3 LIST: scan failed");
        let found = keys
            .iter()
            .any(|k| k.path.file_name().is_some_and(|n| n == "id_crud_test_key"));
        assert!(
            found,
            "Step 3 LIST: key not found in inventory ({} keys scanned)",
            keys.len()
        );
        eprintln!("✓ Step 3: LIST returns the key");

        mgr.keys()
            .rename("id_crud_test_key", "id_crud_test_v2")
            .await
            .expect("Step 4 RENAME: rename failed");
        eprintln!("✓ Step 4: RENAME to 'id_crud_test_v2'");

        let new_private = std::path::Path::new(&home).join(".ssh/id_crud_test_v2");
        assert!(
            !private.exists(),
            "Step 5 VERIFY: old private key still exists"
        );
        assert!(
            new_private.exists(),
            "Step 5 VERIFY: new private key missing"
        );
        eprintln!("✓ Step 5: VERIFY old gone, new exists");

        let del_params = toride_ssh::KeyDeleteParams {
            name: "id_crud_test_v2".to_owned(),
            remove_public: true,
            remove_certificate: true,
            remove_from_agent: false,
            remove_from_config: false,
            backup: false,
        };
        mgr.keys()
            .delete(del_params)
            .await
            .expect("Step 6 DELETE: deletion failed");
        eprintln!("✓ Step 6: DELETE 'id_crud_test_v2'");

        assert!(
            !new_private.exists(),
            "Step 7 VERIFY: private key still exists after delete"
        );
        let new_public = std::path::Path::new(&home).join(".ssh/id_crud_test_v2.pub");
        assert!(
            !new_public.exists(),
            "Step 7 VERIFY: public key still exists after delete"
        );
        eprintln!("✓ Step 7: VERIFY both files gone");
        eprintln!("✅ key_full_crud_lifecycle PASSED");
    }

    #[tokio::test]
    async fn config_host_full_crud_lifecycle() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.config();

        svc.edit(|ast| {
            toride_ssh::config::ConfigService::add_host(
                ast,
                "test-server",
                vec![
                    ("HostName".to_owned(), "10.0.0.1".to_owned()),
                    ("user".to_owned(), "admin".to_owned()),
                    ("port".to_owned(), "2222".to_owned()),
                ],
            )
        })
        .await
        .expect("Step 1 ADD: config add_host failed");
        eprintln!("✓ Step 1: ADD host 'test-server'");

        let ast = svc.load().await.expect("Step 2 VERIFY: config load failed");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("test-server"),
            "Step 2 VERIFY: 'test-server' not in config:\n{content}"
        );
        assert!(
            content.contains("10.0.0.1"),
            "Step 2 VERIFY: hostname '10.0.0.1' not in config:\n{content}"
        );
        eprintln!("✓ Step 2: VERIFY host block in config");

        svc.edit(|ast| {
            let _ = toride_ssh::config::ConfigService::remove_host(ast, "test-server");
            toride_ssh::config::ConfigService::add_host(
                ast,
                "test-server",
                vec![
                    ("hostname".to_owned(), "10.0.0.99".to_owned()),
                    ("user".to_owned(), "deploy".to_owned()),
                    ("port".to_owned(), "443".to_owned()),
                ],
            )
        })
        .await
        .expect("Step 3 EDIT: config edit failed");
        eprintln!("✓ Step 3: EDIT host with new values");

        let ast = svc.load().await.expect("Step 4 VERIFY: config load failed");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("10.0.0.99"),
            "Step 4 VERIFY: new hostname not in config:\n{content}"
        );
        assert!(
            !content.contains("10.0.0.1"),
            "Step 4 VERIFY: old hostname still in config:\n{content}"
        );
        eprintln!("✓ Step 4: VERIFY new values present, old gone");

        svc.edit(|ast| toride_ssh::config::ConfigService::remove_host(ast, "test-server"))
            .await
            .expect("Step 5 REMOVE: config remove failed");
        eprintln!("✓ Step 5: REMOVE host 'test-server'");

        let ast = svc.load().await.expect("Step 6 VERIFY: config load failed");
        let content = ast.to_string_lossless();
        assert!(
            !content.contains("test-server"),
            "Step 6 VERIFY: 'test-server' still in config:\n{content}"
        );
        eprintln!("✓ Step 6: VERIFY host block gone");
        eprintln!("✅ config_host_full_crud_lifecycle PASSED");
    }

    #[tokio::test]
    async fn authorized_keys_full_crud_lifecycle() {
        const TEST_PUB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI crud-test@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.authorized_keys();

        svc.add(TEST_PUB_KEY, Some("crud-test"), None)
            .await
            .expect("Step 1 ADD: authorized_keys add failed");
        eprintln!("✓ Step 1: ADD key to authorized_keys");

        let entries = svc.list().await.expect("Step 2 VERIFY: list failed");
        assert!(
            !entries.is_empty(),
            "Step 2 VERIFY: authorized_keys list is empty after add"
        );
        let matched = entries
            .iter()
            .find(|e| e.comment.as_deref() == Some("crud-test"));
        assert!(
            matched.is_some(),
            "Step 2 VERIFY: no entry with comment 'crud-test' found"
        );
        eprintln!(
            "✓ Step 2: VERIFY list returns {} entry/entries",
            entries.len()
        );

        let entry = matched.expect("entry must exist");
        let fp = entry
            .fingerprint()
            .expect("Step 3 REMOVE: could not compute fingerprint");
        let removed = svc
            .remove(&fp)
            .await
            .expect("Step 3 REMOVE: authorized_keys remove failed");
        assert!(
            removed > 0,
            "Step 3 REMOVE: remove returned 0 count (nothing deleted)"
        );
        eprintln!("✓ Step 3: REMOVE key (fingerprint: {fp})");

        let entries = svc.list().await.expect("Step 4 VERIFY: list failed");
        let still_exists = entries
            .iter()
            .any(|e| e.comment.as_deref() == Some("crud-test"));
        assert!(
            !still_exists,
            "Step 4 VERIFY: key still present after removal"
        );
        eprintln!("✓ Step 4: VERIFY key removed from authorized_keys");
        eprintln!("✅ authorized_keys_full_crud_lifecycle PASSED");
    }

    #[tokio::test]
    async fn known_hosts_crud_lifecycle() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.known_hosts();

        let add_result = svc.add("localhost").await;
        if add_result.is_err() {
            eprintln!(
                "⚠ Step 1 ADD: ssh-keyscan localhost failed ({:?}) — skipping known_hosts test",
                add_result.err()
            );
            eprintln!("ℹ This is expected if no SSH server runs on localhost");
            return;
        }
        eprintln!("✓ Step 1: ADD localhost to known_hosts");

        let kh_file =
            std::path::Path::new(&std::env::var("HOME").expect("HOME")).join(".ssh/known_hosts");
        assert!(kh_file.exists(), "Step 2 VERIFY: known_hosts file missing");
        let content = std::fs::read_to_string(&kh_file).expect("read known_hosts");
        assert!(
            !content.trim().is_empty(),
            "Step 2 VERIFY: known_hosts is empty"
        );
        eprintln!("✓ Step 2: VERIFY known_hosts file has content");

        svc.remove("localhost")
            .await
            .expect("Step 3 REMOVE: known_hosts remove failed");
        eprintln!("✓ Step 3: REMOVE localhost from known_hosts");

        let content_after = std::fs::read_to_string(&kh_file).unwrap_or_default();
        eprintln!(
            "✓ Step 4: VERIFY remove succeeded (known_hosts now has {} bytes)",
            content_after.len()
        );
        eprintln!("✅ known_hosts_crud_lifecycle PASSED");
    }

    #[tokio::test]
    async fn execute_op_pipeline_round_trip() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let home = std::env::var("HOME").expect("HOME");

        let op = SshOp::KeyCreate {
            name: "pipeline-key".into(),
            key_type: "Ed25519".into(),
            comment: "pipeline-test@toride".into(),
            passphrase: None,
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 1 CREATE via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 1: execute_op(KeyCreate) — {}", result.unwrap());

        let key_path = std::path::Path::new(&home).join(".ssh/pipeline-key");
        assert!(
            key_path.exists(),
            "Step 2 VERIFY: private key missing at {key_path:?}"
        );
        eprintln!("✓ Step 2: VERIFY key file on disk");

        let op = SshOp::KeyRename {
            old_name: "pipeline-key".into(),
            new_name: "pipeline-renamed".into(),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 3 RENAME via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 3: execute_op(KeyRename) — {}", result.unwrap());

        assert!(!key_path.exists(), "Step 4 VERIFY: old key still exists");
        let renamed_path = std::path::Path::new(&home).join(".ssh/pipeline-renamed");
        assert!(renamed_path.exists(), "Step 4 VERIFY: renamed key missing");
        eprintln!("✓ Step 4: VERIFY old gone, renamed exists");

        let op = SshOp::KeyDelete {
            name: "pipeline-renamed".into(),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 5 DELETE via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 5: execute_op(KeyDelete) — {}", result.unwrap());

        assert!(
            !renamed_path.exists(),
            "Step 6 VERIFY: key still exists after delete"
        );
        eprintln!("✓ Step 6: VERIFY key file gone");

        let op = SshOp::ConfigAddHost {
            name: "pipeline-host".into(),
            host_name: Some("192.168.1.50".into()),
            user: Some("testuser".into()),
            port: Some(22),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 7 CONFIG ADD via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 7: execute_op(ConfigAddHost) — {}", result.unwrap());

        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ast = mgr.config().load().await.expect("load config");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("pipeline-host"),
            "Step 8 VERIFY: 'pipeline-host' not in config:\n{content}"
        );
        eprintln!("✓ Step 8: VERIFY host in config");

        let op = SshOp::ConfigRemoveHost {
            name: "pipeline-host".into(),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 9 CONFIG REMOVE via execute_op failed: {:?}",
            result.err()
        );
        eprintln!(
            "✓ Step 9: execute_op(ConfigRemoveHost) — {}",
            result.unwrap()
        );

        let ast = mgr.config().load().await.expect("load config");
        let content = ast.to_string_lossless();
        assert!(
            !content.contains("pipeline-host"),
            "Step 10 VERIFY: 'pipeline-host' still in config:\n{content}"
        );
        eprintln!("✓ Step 10: VERIFY host gone from config");
        eprintln!("✅ execute_op_pipeline_round_trip PASSED");
    }

    #[test]
    fn would_lock_out_refuses_literal_root() {
        let err = would_lock_out("deny", "root").expect("must refuse root");
        assert!(err.revert_optimistic, "lockout refusal must revert");
        assert!(
            err.message.contains("root"),
            "message should mention root: {}",
            err.message
        );
        assert!(
            would_lock_out("reset", "root").is_some(),
            "reset root must also be refused"
        );
    }

    #[test]
    fn would_lock_out_refuses_current_user_by_name() {
        let Some(current) = current_username() else {
            return;
        };
        if current == "root" {
            return;
        }
        let err = would_lock_out("deny", &current).expect("must refuse to deny the current user");
        assert!(err.revert_optimistic);
    }

    #[test]
    fn would_lock_out_refuses_current_user_by_uid_fallback() {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return;
        }
        if let Some(name) = current_username()
            && name != "root"
        {
            assert_eq!(
                uid_for_username(&name),
                Some(euid),
                "forward/reverse lookups disagree on current user {name}"
            );
            assert!(
                would_lock_out("reset", &name).is_some(),
                "must refuse to reset the current user {name}"
            );
        }
    }

    #[test]
    fn would_lock_out_refuses_unresolvable_user() {
        let result = would_lock_out("deny", "definitely-not-a-real-user-xyzzy");
        assert!(
            result.is_some(),
            "unresolvable user must be refused (refuse-by-default), got {result:?}"
        );
        let err = result.expect("checked Some above");
        assert!(err.revert_optimistic);
        assert!(
            err.message.contains("cannot resolve"),
            "refusal must explain the unresolvable-account reason: {err:?}"
        );
    }

    #[test]
    fn map_sshd_error_reverts_on_validation_failure() {
        let err = map_sshd_error(
            "deny",
            "alice",
            &toride_ssh::Error::SshdConfigInvalid("line 1: bad option".into()),
        );
        assert!(err.revert_optimistic, "validation failure must revert");
        assert!(err.message.contains("alice"));
    }

    #[test]
    fn map_sshd_error_reverts_on_binary_missing() {
        let err = map_sshd_error(
            "deny",
            "alice",
            &toride_ssh::Error::SshdNotFound("sshd: command not found".into()),
        );
        assert!(err.revert_optimistic, "binary-missing must revert");
    }

    #[test]
    fn map_sshd_error_reverts_on_sudo_failure() {
        let err = map_sshd_error(
            "deny",
            "alice",
            &toride_ssh::Error::SudoFailed("a password is required".into()),
        );
        assert!(err.revert_optimistic, "sudo failure must revert");
    }

    #[test]
    fn map_sshd_error_reverts_on_pre_install_config_write_failure() {
        let err = map_sshd_error(
            "deny",
            "alice",
            &toride_ssh::Error::ConfigWriteFailed("failed to install sshd_config: EBUSY".into()),
        );
        assert!(
            err.revert_optimistic,
            "pre-install ConfigWriteFailed must revert"
        );
        assert!(
            !err.message.contains("mode could not be set"),
            "ConfigWriteFailed must not carry the dropped chmod annotation: {}",
            err.message
        );
    }

    #[test]
    fn map_sshd_error_chmod_failure_reverts_without_false_installed_annotation() {
        let err = map_sshd_error(
            "deny",
            "alice",
            &toride_ssh::Error::ConfigWriteFailed("failed to chmod sshd_config: EPERM".into()),
        );
        assert!(
            err.revert_optimistic,
            "chmod failure must revert (live config untouched under the invariant)"
        );
        assert!(
            !err.message.contains("installed"),
            "chmod failure must NOT claim the config was installed (false premise): {}",
            err.message
        );
        assert!(
            !err.message.contains("mode could not be set"),
            "chmod failure must not carry the dropped false annotation: {}",
            err.message
        );
        assert!(
            err.message.contains("chmod"),
            "message must still surface the underlying chmod step: {}",
            err.message
        );
    }

    #[test]
    fn parse_sshd_config_from_excludes_match_scoped_directives() {
        let contents = [
            "PasswordAuthentication no",
            "Match Address 10.0.0.0/8",
            "    PasswordAuthentication yes",
            "    PermitRootLogin yes",
        ]
        .join("\n");
        let config = parse_sshd_config_from(&contents);
        assert_eq!(
            config.get("passwordauthentication"),
            Some(&"no".to_string()),
            "global value must win; indented Match body must not leak"
        );
        assert!(
            config
                .get("permitrootlogin")
                .map(std::string::String::as_str)
                .is_none_or(|v| v != "yes"),
            "Match-scoped PermitRootLogin must not appear in the global map: {config:?}"
        );
        assert_eq!(
            config.len(),
            1,
            "exactly one global directive expected, got {config:?}"
        );
    }

    #[test]
    fn map_sshd_error_reverts_on_io_failure() {
        let err = map_sshd_error(
            "deny",
            "alice",
            &toride_ssh::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "permission denied reading sshd_config",
            )),
        );
        assert!(
            err.revert_optimistic,
            "pre-write Io load failure (disk untouched) must revert the optimistic update"
        );
        assert!(
            err.message.contains("alice"),
            "message must name the target: {}",
            err.message
        );
    }

    #[test]
    fn would_lock_out_with_uid_refuses_resolved_euid() {
        let err = would_lock_out_with_uid("deny", "weird-uid-account", 501, Some(501))
            .expect("uid == euid must be refused even when name lookup failed");
        assert!(err.revert_optimistic);
        assert!(err.message.contains("weird-uid-account"));
    }

    #[test]
    fn would_lock_out_with_uid_refuses_uid_zero() {
        let err =
            would_lock_out_with_uid("reset", "toor", 1000, Some(0)).expect("uid 0 must be refused");
        assert!(err.revert_optimistic);
        assert!(err.message.contains("toor"));
    }

    #[test]
    fn would_lock_out_with_uid_allows_unrelated() {
        let result = would_lock_out_with_uid("deny", "someone-else", 1000, Some(501));
        assert!(
            result.is_none(),
            "unrelated uid must not be refused, got {result:?}"
        );
    }

    #[test]
    fn would_lock_out_with_uid_refuses_unresolvable_uid() {
        let result = would_lock_out_with_uid("deny", "ghost", 1000, None);
        assert!(
            result.is_some(),
            "unresolvable uid (None) must be refused (refuse-by-default), got {result:?}"
        );
        let err = result.expect("checked Some above");
        assert!(err.revert_optimistic);
        assert!(
            err.message.contains("cannot resolve"),
            "refusal must explain the unresolvable-account reason: {err:?}"
        );
    }

    #[test]
    fn would_lock_out_with_uid_refuses_unresolvable_on_reset() {
        let result = would_lock_out_with_uid("reset", "ghost", 1000, None);
        assert!(
            result.is_some(),
            "unresolvable uid must be refused on reset too, got {result:?}"
        );
    }

    fn seed_authorized_keys(lines: &[&str]) {
        let home = std::env::var("HOME").expect("HOME set");
        let path = std::path::Path::new(&home).join(".ssh/authorized_keys");
        let body = lines.join("\n");
        std::fs::write(&path, format!("{body}\n")).expect("write authorized_keys");
    }

    #[tokio::test]
    async fn would_lock_out_authorized_key_refuses_removing_last_key() {
        const TEST_PUB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI last-key@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();

        seed_authorized_keys(&[TEST_PUB_KEY]);

        let entries = svc.list().await.expect("list");
        assert_eq!(entries.len(), 1, "seeded one key");
        let fp = entries[0].fingerprint().expect("fingerprint").clone();

        let guard = would_lock_out_authorized_key(&svc, &fp)
            .await
            .expect("must refuse to remove the operator's last key");
        assert!(
            guard.revert_optimistic,
            "last-key removal refusal must revert"
        );
        assert!(
            guard.message.contains("last key"),
            "refusal must explain it is the last key: {}",
            guard.message
        );
    }

    #[tokio::test]
    async fn would_lock_out_authorized_key_allows_when_a_key_remains() {
        const KEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI keep-a@toride";
        const KEY_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP9fG4eJ8kL3mN6oQ2rS5tU7vWxYzAbCdEfGhIjKlMnO remove-b@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();

        seed_authorized_keys(&[KEY_A, KEY_B]);

        let entries = svc.list().await.expect("list");
        assert_eq!(entries.len(), 2, "seeded two keys");
        let target_pk = ssh_key::PublicKey::from_openssh(KEY_B).expect("parse B");
        let fp = target_pk.fingerprint(ssh_key::HashAlg::Sha256).to_string();

        let guard = would_lock_out_authorized_key(&svc, &fp).await;
        assert!(
            guard.is_none(),
            "removal that leaves a key must be allowed, got {guard:?}"
        );
    }

    #[tokio::test]
    async fn would_lock_out_authorized_key_allows_empty_file() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();
        let guard = would_lock_out_authorized_key(&svc, "SHA256:nonexistent").await;
        assert!(
            guard.is_none(),
            "empty file must be allowed (nothing to lock out), got {guard:?}"
        );
    }

    #[tokio::test]
    async fn would_lock_out_authorized_key_refuses_when_all_keys_match() {
        const DUP_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI dup@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();

        seed_authorized_keys(&[DUP_KEY, DUP_KEY, DUP_KEY]);

        let entries = svc.list().await.expect("list");
        assert_eq!(entries.len(), 3, "seeded three copies");
        let fp = entries[0].fingerprint().expect("fingerprint").clone();

        let guard = would_lock_out_authorized_key(&svc, &fp)
            .await
            .expect("must refuse when every matching entry shares the fingerprint");
        assert!(guard.revert_optimistic);
        assert!(guard.message.contains("last key"));
    }

    #[tokio::test]
    async fn execute_op_authorized_key_remove_refuses_self_lockout() {
        const TEST_PUB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI last-key@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();

        seed_authorized_keys(&[TEST_PUB_KEY]);

        let entries = svc.list().await.expect("list");
        assert_eq!(entries.len(), 1, "seeded one key");
        let fp = entries[0].fingerprint().expect("fingerprint").clone();

        let home = std::env::var("HOME").expect("HOME");
        let ak_path = std::path::Path::new(&home).join(".ssh/authorized_keys");
        let before = std::fs::read_to_string(&ak_path).expect("read before");

        let result = execute_op(SshOp::AuthorizedKeyRemove {
            fingerprint: fp.clone(),
        })
        .await;
        let err = result.expect_err("must refuse to remove the operator's last key");
        assert!(
            err.revert_optimistic,
            "self-lockout refusal must revert, got {err:?}"
        );

        let after = std::fs::read_to_string(&ak_path).expect("read after");
        assert_eq!(
            before, after,
            "authorized_keys must be byte-for-byte unchanged on refusal"
        );
        assert!(
            after.contains("last-key@toride"),
            "the sole key must still be present after the refused op"
        );
    }

    #[test]
    fn nss_uid_for_username_resolves_real_local_user() {
        let uid = nss_uid_for_username("root")
            .expect("NSS must resolve the 'root' account on any Unix system");
        assert_eq!(uid, 0, "root's UID via getpwnam_r must be 0; got {uid}");
    }

    #[test]
    fn nss_username_for_uid_resolves_uid_zero_to_root() {
        let name = nss_username_for_uid(0).expect("NSS must resolve UID 0 on any Unix system");
        assert_eq!(
            name, "root",
            "UID 0 must resolve to 'root' via getpwuid_r; got {name:?}"
        );
    }

    #[test]
    fn nss_uid_for_username_returns_none_for_nonexistent() {
        let uid = nss_uid_for_username("toride-definitely-no-such-user-zyxw");
        assert!(
            uid.is_none(),
            "nonexistent account must be None via NSS, got {uid:?}"
        );
    }

    #[test]
    fn uid_for_username_resolves_root_via_full_chain() {
        let uid = uid_for_username("root").expect("uid_for_username must resolve 'root'");
        assert_eq!(uid, 0);
    }

    fn snapshot_sshd_config() -> Option<Vec<u8>> {
        std::fs::read("/etc/ssh/sshd_config").ok()
    }

    #[tokio::test]
    async fn execute_op_sshd_deny_root_refused_with_revert_and_disk_unchanged() {
        let before = snapshot_sshd_config();
        let result = execute_op(SshOp::SshdDenyUser {
            username: "root".into(),
        })
        .await;
        let after = snapshot_sshd_config();

        let err = result.expect_err(
            "execute_op(SshdDenyUser{root}) must be refused by the backend lockout guard",
        );
        assert!(
            err.revert_optimistic,
            "root denial refusal must mark the optimistic update for immediate revert: {err:?}"
        );
        assert!(
            err.message.contains("root"),
            "refusal message must name root: {err:?}"
        );
        assert_eq!(
            before, after,
            "/etc/ssh/sshd_config must be unchanged after a refused root denial"
        );
    }

    #[tokio::test]
    async fn execute_op_sshd_reset_root_refused_with_revert_and_disk_unchanged() {
        let before = snapshot_sshd_config();
        let result = execute_op(SshOp::SshdResetUserAccess {
            username: "root".into(),
        })
        .await;
        let after = snapshot_sshd_config();

        let err = result.expect_err(
            "execute_op(SshdResetUserAccess{root}) must be refused by the backend lockout guard",
        );
        assert!(
            err.revert_optimistic,
            "root reset refusal must mark the optimistic update for immediate revert: {err:?}"
        );
        assert_eq!(
            before, after,
            "/etc/ssh/sshd_config must be unchanged after a refused root reset"
        );
    }

    #[tokio::test]
    async fn would_lock_out_async_refuses_root_like_sync() {
        let sync_err = would_lock_out("deny", "root").expect("sync refuses root");
        let async_err = would_lock_out_async("deny", "root")
            .await
            .expect("async must refuse root too");
        assert!(
            async_err.revert_optimistic,
            "async root refusal must revert: {async_err:?}"
        );
        assert_eq!(
            async_err.message, sync_err.message,
            "async and sync root refusals must produce identical messages"
        );
        assert!(async_err.message.contains("root"));
    }

    #[tokio::test]
    async fn would_lock_out_async_refuses_unresolvable_user() {
        let result =
            would_lock_out_async("deny", "toride-definitely-no-such-user-async-zyxw").await;
        let err = result.expect("async must refuse an unresolvable user");
        assert!(err.revert_optimistic);
        assert!(
            err.message.contains("cannot resolve") || err.message.contains("refusing"),
            "async unresolvable refusal must explain: {err:?}"
        );
    }

    #[tokio::test]
    async fn would_lock_out_async_denial_matches_sync_for_current_user() {
        let Some(current) = current_username() else {
            return;
        };
        if current == "root" {
            return;
        }
        let sync_some = would_lock_out("deny", &current).is_some();
        let async_some = would_lock_out_async("deny", &current).await.is_some();
        assert_eq!(
            sync_some, async_some,
            "async and sync lockout verdicts must agree for the current user '{current}'"
        );
        assert!(
            async_some,
            "async must refuse denying the current user '{current}'"
        );
    }

    const PREVIEW_PUB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI \
         alice@toride";

    fn write_authorized_keys(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
        let ssh_dir = dir.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("create .ssh");
        let path = ssh_dir.join("authorized_keys");
        std::fs::write(&path, contents).expect("write authorized_keys");
        path
    }

    fn scan_previews(
        ssh_dir: &std::path::Path,
    ) -> Vec<crate::ui::screens::ssh::AuthorizedKeyPreview> {
        scan_user_ssh_dir(&[], ssh_dir).authorized_keys_preview
    }

    #[test]
    fn collect_authorized_keys_preview_parses_valid_key_with_comment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().to_path_buf();
        write_authorized_keys(&dir_path, PREVIEW_PUB_KEY);
        let ssh_dir = dir_path.join(".ssh");
        let previews = scan_previews(&ssh_dir);
        assert_eq!(previews.len(), 1, "one valid key → one preview");
        let p = &previews[0];
        assert_eq!(p.key_type, "ssh-ed25519", "key type from first token");
        assert_eq!(
            p.comment.as_deref(),
            Some("alice@toride"),
            "trailing comment captured"
        );
        assert_eq!(p.line, 1, "1-based line number");
        assert!(
            p.fingerprint.starts_with("SHA256:"),
            "fingerprint computed for a parseable key: {}",
            p.fingerprint
        );
        assert!(
            !p.fingerprint.contains("(unknown)"),
            "a valid key must not fall back to the unknown fingerprint"
        );
    }

    #[test]
    fn collect_authorized_keys_preview_handles_options_prefixed_key() {
        let line = format!("no-port-forwarding,no-agent-forwarding {PREVIEW_PUB_KEY}");
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().to_path_buf();
        write_authorized_keys(&dir_path, &line);
        let ssh_dir = dir_path.join(".ssh");
        let previews = scan_previews(&ssh_dir);
        assert_eq!(
            previews.len(),
            1,
            "options-prefixed key parses to one entry"
        );
        let p = &previews[0];
        assert_eq!(
            p.key_type, "ssh-ed25519",
            "options token skipped → key type is the second token"
        );
        assert_eq!(p.comment.as_deref(), Some("alice@toride"));
        assert_eq!(p.line, 1);
    }

    #[test]
    fn collect_authorized_keys_preview_skips_malformed_and_single_field_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().to_path_buf();
        let contents = format!(
            "# a comment line\n\n\
             not-a-key\n\
             {PREVIEW_PUB_KEY}\n\
             just-one-token\n\
             {PREVIEW_PUB_KEY}\n"
        );
        write_authorized_keys(&dir_path, &contents);
        let ssh_dir = dir_path.join(".ssh");
        let previews = scan_previews(&ssh_dir);
        assert_eq!(previews.len(), 2, "only full key lines parse: {previews:?}");
        assert_eq!(previews[0].line, 4, "first valid key is on file line 4");
        assert_eq!(previews[1].line, 6, "second valid key is on file line 6");
    }

    #[test]
    fn collect_authorized_keys_preview_enforces_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().to_path_buf();
        let key = PREVIEW_PUB_KEY;
        let mut contents = String::new();
        for _ in 0..=(USER_PREVIEW_CAP + 1) {
            contents.push_str(key);
            contents.push('\n');
        }
        write_authorized_keys(&dir_path, &contents);
        let ssh_dir = dir_path.join(".ssh");
        let scan = scan_user_ssh_dir(&[], &ssh_dir);
        assert_eq!(
            scan.authorized_keys_preview.len(),
            USER_PREVIEW_CAP,
            "previews must cap at USER_PREVIEW_CAP"
        );
        assert_eq!(
            scan.authorized_key_count,
            USER_PREVIEW_CAP + 2,
            "count counts every entry even past the preview cap"
        );
    }

    #[test]
    fn collect_authorized_keys_preview_missing_file_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("create .ssh");
        let previews = scan_previews(&ssh_dir);
        assert!(previews.is_empty(), "missing authorized_keys → empty vec");
    }

    #[test]
    fn collect_authorized_keys_preview_single_field_key_type_falls_back_gracefully() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().to_path_buf();
        write_authorized_keys(&dir_path, "ssh-ed25519\n");
        let ssh_dir = dir_path.join(".ssh");
        let previews = scan_previews(&ssh_dir);
        assert!(
            previews.is_empty(),
            "a lone key-type token with no blob must be dropped, not panic"
        );
    }

    fn mtime_of(path: &std::path::Path) -> std::time::SystemTime {
        std::fs::metadata(path)
            .expect("stat fixture")
            .modified()
            .expect("mtime")
    }

    fn rewrite_with_new_stamp(
        path: &std::path::Path,
        previous: std::time::SystemTime,
        content: &str,
    ) {
        loop {
            std::fs::write(path, content).expect("rewrite fixture");
            if mtime_of(path) != previous {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    fn known_host_summary(entries: &[KnownHostEntry]) -> Vec<(String, String, Vec<String>)> {
        entries
            .iter()
            .map(|e| {
                (
                    e.hosts.join(","),
                    e.key_type.clone(),
                    e.fingerprints.clone(),
                )
            })
            .collect()
    }

    fn auth_key_summary(entries: &[AuthorizedKeyEntry]) -> Vec<(String, Option<String>, String)> {
        entries
            .iter()
            .map(|e| (e.key_type.clone(), e.comment.clone(), e.fingerprint.clone()))
            .collect()
    }

    fn known_hosts_line(host: &str) -> String {
        let (key_type, rest) = PREVIEW_PUB_KEY
            .split_once(' ')
            .expect("type + blob + comment");
        let (blob, _comment) = rest.split_once(' ').unwrap_or((rest, ""));
        format!("{host} {key_type} {blob}")
    }

    fn known_hosts_slot(cache: &SshStateCache) -> Option<Arc<Vec<KnownHostEntry>>> {
        cache
            .known_hosts
            .lock()
            .expect("lock")
            .as_ref()
            .map(|s| Arc::clone(&s.value))
    }

    #[tokio::test]
    async fn known_hits_cache_until_file_changes() {
        let _lock = acquire_home_lock().await;
        let home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let paths = toride_ssh::SshPaths::new().expect("paths");
        let known_hosts_path = paths.known_hosts_path();
        std::fs::write(known_hosts_path, known_hosts_line("example.com")).expect("write kh");

        let cache = SshStateCache::new();
        let first = collect_known_hosts_cached(&mgr, Some(&paths), &cache)
            .await
            .expect("first collect");
        assert_eq!(first.len(), 1, "one host line → one grouped entry");
        let stored = known_hosts_slot(&cache).expect("slot populated after miss");

        let second = collect_known_hosts_cached(&mgr, Some(&paths), &cache)
            .await
            .expect("second collect");
        assert_eq!(
            known_host_summary(&first),
            known_host_summary(&second),
            "cache hit must be value-identical"
        );
        let stored_after = known_hosts_slot(&cache).expect("slot still populated");
        assert!(
            Arc::ptr_eq(&stored, &stored_after),
            "an unchanged file must not rebuild the cached list"
        );

        let two_hosts = format!(
            "{}\n{}",
            known_hosts_line("example.com"),
            known_hosts_line("other.com")
        );
        rewrite_with_new_stamp(known_hosts_path, mtime_of(known_hosts_path), &two_hosts);
        let third = collect_known_hosts_cached(&mgr, Some(&paths), &cache)
            .await
            .expect("third collect after rewrite");
        assert_eq!(third.len(), 2, "invalidation must re-parse the new content");
        assert_ne!(known_host_summary(&third), known_host_summary(&first));
        drop(home);
    }

    #[tokio::test]
    async fn authorized_keys_hits_cache_until_file_changes() {
        let _lock = acquire_home_lock().await;
        let home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let paths = toride_ssh::SshPaths::new().expect("paths");
        let ak_path = paths.authorized_keys_path();
        std::fs::write(ak_path, PREVIEW_PUB_KEY).expect("write ak");

        let cache = SshStateCache::new();
        let first = collect_authorized_keys_cached(&mgr, Some(&paths), &cache)
            .await
            .expect("first collect");
        assert_eq!(first.len(), 1);
        let stored = cache
            .authorized_keys
            .lock()
            .expect("lock")
            .as_ref()
            .map(|s| Arc::clone(&s.value))
            .expect("slot populated after miss");

        let second = collect_authorized_keys_cached(&mgr, Some(&paths), &cache)
            .await
            .expect("second collect");
        assert_eq!(
            auth_key_summary(&first),
            auth_key_summary(&second),
            "cache hit must be value-identical"
        );
        let stored_after = cache
            .authorized_keys
            .lock()
            .expect("lock")
            .as_ref()
            .map(|s| Arc::clone(&s.value))
            .expect("slot still populated");
        assert!(
            Arc::ptr_eq(&stored, &stored_after),
            "unchanged authorized_keys must be served from the cache"
        );

        rewrite_with_new_stamp(ak_path, mtime_of(ak_path), "");
        let third = collect_authorized_keys_cached(&mgr, Some(&paths), &cache)
            .await
            .expect("third collect");
        assert!(third.is_empty(), "key removal must invalidate the cache");
        drop(home);
    }

    #[tokio::test]
    async fn certificates_serve_cached_parse_and_recompute_validity() {
        let _lock = acquire_home_lock().await;
        let home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ssh_dir = toride_ssh::SshPaths::new()
            .expect("paths")
            .ssh_dir()
            .to_path_buf();
        let cert_path = ssh_dir.join("id_test-cert.pub");
        std::fs::write(&cert_path, "not a certificate").expect("write cert fixture");

        let cache = SshStateCache::new();
        let stamp = stamp_path(&cert_path).expect("stampable cert fixture");
        let injected = vec![(
            cert_path.clone(),
            toride_ssh::certificate::CertificateInfo {
                serial: 42,
                key_type: "ssh-ed25519".into(),
                key_id: "injected-key-id".into(),
                valid_principals: vec!["alice".into()],
                valid_after: 0,
                valid_before: u64::MAX,
                critical_options: Vec::new(),
                extensions: Vec::new(),
                ca_fingerprint: None,
                is_host: false,
            },
        )];
        *cache.certificates.lock().expect("lock") = Some(Stamped {
            stamp: vec![(cert_path.clone(), stamp)],
            value: Arc::new(injected),
        });

        let entries = collect_certificates_cached(&mgr, &cache)
            .await
            .expect("cached collect");
        assert_eq!(entries.len(), 1, "cached parse must be served verbatim");
        assert_eq!(entries[0].key_id, "injected-key-id");
        assert_eq!(entries[0].serial, 42);
        assert!(
            entries[0].is_valid,
            "validity is recomputed per read against the current clock"
        );
        drop(home);
    }

    #[tokio::test]
    async fn security_fold_previews_match_file_scan() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let ssh_dir = std::path::PathBuf::from(std::env::var("HOME").expect("TempHome sets HOME"))
            .join(".ssh");
        let contents =
            format!("# comment\n\n{PREVIEW_PUB_KEY}\ncommand=\"/bin/date\" {PREVIEW_PUB_KEY}\n");
        std::fs::write(ssh_dir.join("authorized_keys"), &contents).expect("write ak");

        let scan = scan_user_ssh_dir(&[], &ssh_dir);
        assert_eq!(scan.authorized_key_count, 2);

        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let entries = mgr
            .authorized_keys()
            .list()
            .await
            .map(ssh_convert::convert_authorized_keys)
            .unwrap_or_default();
        assert_eq!(entries.len(), 2, "fixture must parse into two entries");
        let folded = user_scan_from_entries(&entries);

        assert_eq!(folded.authorized_key_count, scan.authorized_key_count);
        assert_eq!(
            folded.authorized_keys_preview.len(),
            scan.authorized_keys_preview.len()
        );
        for (f, s) in folded
            .authorized_keys_preview
            .iter()
            .zip(scan.authorized_keys_preview.iter())
        {
            assert_eq!(f.key_type, s.key_type);
            assert_eq!(f.comment, s.comment);
            assert_eq!(f.line, s.line);
            assert_eq!(
                f.fingerprint, s.fingerprint,
                "fold must reuse the entries' fingerprints, not recompute a different value"
            );
        }
    }

    #[test]
    fn user_ssh_scan_cache_invalidates_on_authorized_keys_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("mkdir");
        let ak = ssh_dir.join("authorized_keys");
        std::fs::write(&ak, PREVIEW_PUB_KEY).expect("write ak");

        let cache = SshStateCache::new();
        let first = scan_user_ssh_cached(&ssh_dir, None, None, &cache);
        assert_eq!(first.authorized_key_count, 1);
        let stored = cache
            .user_ssh_scans
            .lock()
            .expect("lock")
            .get(&ssh_dir)
            .map(|s| Arc::clone(&s.value))
            .expect("stored after miss");

        let second = scan_user_ssh_cached(&ssh_dir, None, None, &cache);
        assert_eq!(second.authorized_key_count, 1);
        let stored_after = cache
            .user_ssh_scans
            .lock()
            .expect("lock")
            .get(&ssh_dir)
            .map(|s| Arc::clone(&s.value))
            .expect("stored");
        assert!(Arc::ptr_eq(&stored, &stored_after), "hit must not re-scan");

        rewrite_with_new_stamp(
            &ak,
            mtime_of(&ak),
            &format!("{PREVIEW_PUB_KEY}\n{PREVIEW_PUB_KEY}"),
        );
        let third = scan_user_ssh_cached(&ssh_dir, None, None, &cache);
        assert_eq!(third.authorized_key_count, 2, "miss must re-read the file");
    }

    #[test]
    fn user_scan_cacheable_requires_stamps_for_every_file() {
        let cacheable = UserSshStamp {
            key_listing: vec![(
                "id_rsa".into(),
                Some(FileStamp {
                    mtime_ns: 1,
                    len: 10,
                }),
            )],
            auth: Some(FileStamp {
                mtime_ns: 2,
                len: 5,
            }),
        };
        assert!(user_scan_cacheable(&cacheable));

        let uncacheable = UserSshStamp {
            key_listing: vec![
                (
                    "id_rsa".into(),
                    Some(FileStamp {
                        mtime_ns: 1,
                        len: 10,
                    }),
                ),
                ("id_ed25519".into(), None),
            ],
            auth: Some(FileStamp {
                mtime_ns: 2,
                len: 5,
            }),
        };
        assert!(
            !user_scan_cacheable(&uncacheable),
            "an unstampable key file must disable caching for that user"
        );

        let no_auth = UserSshStamp {
            key_listing: vec![(
                "id_rsa".into(),
                Some(FileStamp {
                    mtime_ns: 1,
                    len: 10,
                }),
            )],
            auth: None,
        };
        assert!(!user_scan_cacheable(&no_auth));
    }

    #[test]
    fn user_key_listing_counts_entries_without_stamping_them_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("mkdir");
        std::fs::write(ssh_dir.join("id_rsa"), b"key").expect("id_rsa");
        std::fs::write(ssh_dir.join("id_ed25519"), b"key").expect("id_ed25519");
        std::fs::write(ssh_dir.join("id_ed25519.pub"), b"pub").expect("pub");
        std::fs::write(ssh_dir.join("id_backup.bak"), b"bak").expect("bak");
        std::fs::write(ssh_dir.join("known_hosts"), b"").expect("known_hosts");

        let listing = user_key_listing(&ssh_dir);
        assert_eq!(
            listing.len(),
            2,
            "only the two private keys count: {listing:?}"
        );
        assert_eq!(listing[0].0, "id_ed25519");
        assert_eq!(listing[1].0, "id_rsa");
        assert!(
            listing.iter().all(|(_, s)| s.is_some()),
            "on a stampable filesystem every entry carries its stamp"
        );
    }

    #[test]
    fn user_ssh_scan_fold_skips_file_reads_for_current_user() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("mkdir");
        std::fs::write(ssh_dir.join("authorized_keys"), PREVIEW_PUB_KEY).expect("write ak");

        let entries = vec![AuthorizedKeyEntry {
            key_type: "ssh-ed25519".into(),
            public_key: String::new(),
            comment: Some("folded@toride".into()),
            fingerprint: "SHA256:folded".into(),
            options: None,
            line: 1,
        }];

        let cache = SshStateCache::new();
        let scan = scan_user_ssh_cached(&ssh_dir, Some(&ssh_dir), Some(&entries), &cache);
        assert_eq!(scan.authorized_key_count, 1);
        assert_eq!(scan.authorized_keys_preview.len(), 1);
        assert_eq!(
            scan.authorized_keys_preview[0].comment.as_deref(),
            Some("folded@toride")
        );
        assert_eq!(scan.authorized_keys_preview[0].fingerprint, "SHA256:folded");
        assert!(
            cache.user_ssh_scans.lock().expect("lock").is_empty(),
            "folded scans must not poison the per-user cache"
        );
    }
}
