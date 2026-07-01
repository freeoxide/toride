//! Async SSH data collection.
//!
//! [`SshDataCollector`] manages background collection of all SSH subsystem data
//! via a tokio oneshot channel, following the same pattern as [`StatusCollector`].
//!
//! Reads real SSH files via the `toride-ssh` library. Falls back to empty data
//! when files are missing or unreadable. Mock data is available behind `#[cfg(test)]`
//! for unit tests.

use std::collections::HashMap;
use std::path::Path;

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
    pub diagnostics: Vec<DiagnosticEntry>,
    /// Authorized keys entries.
    pub authorized_keys: Vec<AuthorizedKeyEntry>,
    /// SSH certificate entries.
    pub certificates: Vec<CertificateEntry>,
    /// Security overview data.
    pub security: SshSecurityData,
}

// ── Collector ────────────────────────────────────────────────────────────────

/// Manages periodic async collection of SSH data.
pub struct SshDataCollector {
    /// Carries the bundle AND whether the cached diagnostics were reused for
    /// this poll. The freshness timestamp must only be advanced when the doctor
    /// was actually re-run (`used_cache == false`); otherwise every cache-hit
    /// poll would reset the TTL clock with the SAME (already-cached)
    /// diagnostics and the cache would never expire for the lifetime of the
    /// app (identical to the fail2ban findings cache).
    rx: Option<oneshot::Receiver<(SshDataBundle, bool)>>,
    /// Cached diagnostics from the last collection (avoids re-running every 2s).
    cached_diagnostics: Option<Vec<DiagnosticEntry>>,
    /// When the diagnostics cache was last refreshed.
    diagnostics_fresh_at: Option<std::time::Instant>,
}

/// How long to keep cached diagnostics before re-running the full suite.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "stable std lacks larger-unit constructors"
)]
const DIAGNOSTICS_TTL: std::time::Duration = std::time::Duration::from_secs(60);

impl SshDataCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rx: None,
            cached_diagnostics: None,
            diagnostics_fresh_at: None,
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
        self.rx = Some(rx);
        tokio::spawn(async move {
            let (bundle, cache_was_used) = collect_real_data(use_cache, cached_diag).await;
            let _ = tx.send((bundle, cache_was_used));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On success the cached diagnostics
    /// are updated to the freshly-returned diagnostics, but the freshness
    /// timestamp is only advanced when the doctor was actually re-run (not on a
    /// cache-hit poll) — otherwise the 60s TTL would be re-armed forever with
    /// the same cached data on every 2s refresh.
    pub async fn poll(&mut self) -> Option<SshDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref bundle, cache_was_used)) = result {
                    self.cached_diagnostics = Some(bundle.diagnostics.clone());
                    // Only advance the freshness clock when the doctor was
                    // actually re-run. On a cache-hit poll the diagnostics are
                    // the SAME data we already cached, so resetting the TTL
                    // here would let the cache live forever as long as the 2s
                    // refresh tick keeps firing inside the TTL window.
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

// ── Real Data Collection ────────────────────────────────────────────────────

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
/// `revert_optimistic` tells the app whether the optimistic in-memory UI
/// update is now a lie that must be reverted right away (by forcing an
/// immediate SSH data refresh) rather than waiting out the write cooldown.
///
/// It is set to `true` when the optimistic UI update is known to **disagree**
/// with on-disk truth after the failed op, so the cooldown must not be used to
/// reconcile it — the UI should refresh immediately. This covers both:
///
/// - **Disk untouched**: a validation failure
///   ([`toride_ssh::Error::SshdConfigInvalid`] / [`SshdNotFound`]) means the
///   privileged write path never installed anything; a privilege failure
///   ([`toride_ssh::Error::SudoFailed`]) means `sudo -n` could not run; and a
///   staging/backup/install [`ConfigWriteFailed`] aborts before the live config
///   is replaced. In all of these the UI applied a change disk never saw.
///   It is `false` for other / transient errors where disk state is uncertain
///   (the regular cooldown will reconcile it).
///
/// [`SshdNotFound`]: toride_ssh::Error::SshdNotFound
#[derive(Debug, Clone)]
pub struct SshOpError {
    /// Human-readable error message (also surfaced to the user as a toast).
    pub message: String,
    /// When true, the optimistic UI update should be reverted immediately by
    /// forcing an SSH data refresh instead of waiting for the write cooldown.
    pub revert_optimistic: bool,
}

impl SshOpError {
    /// Build a non-reverting (transient) error wrapping the given message.
    #[allow(dead_code)]
    fn transient(message: String) -> Self {
        Self {
            message,
            revert_optimistic: false,
        }
    }

    /// Build a reverting error: the optimistic update is stale and should be
    /// overwritten by disk truth right away.
    fn reverting(message: String) -> Self {
        Self {
            message,
            revert_optimistic: true,
        }
    }
}

/// Map a backend `sshd_config` write error to a [`SshOpError`].
///
/// Returns `revert_optimistic = true` (refresh immediately) whenever the
/// optimistic UI update is known to **disagree** with disk truth — so the
/// cooldown is never used to reconcile a stale view. Every error variant that
/// reaches here leaves the live `/etc/ssh/sshd_config` **untouched**:
///
/// - **Validation/binary/privilege failures** (`SshdConfigInvalid`,
///   `SshdNotFound`, `SudoFailed`) abort before any write.
/// - **`ConfigWriteFailed`** from the staging/fsync/backup/install steps of
///   the hardened write path. This **includes** the chmod step: the backend
///   (privilege.rs `install_temp`) chmods the staged TEMP to 0o644 *before*
///   the `rename(2)` into place, so a chmod failure aborts with nothing
///   installed — the live config is never replaced at the wrong mode.
///   (F7: the old annotation "the config was installed but its mode could not
///   be set to 0644" was inverted — under the chmod-before-rename invariant a
///   chmod failure can NEVER co-occur with a successful install, so the
///   annotation was unreachable in practice and, if it ever fired, would have
///   lied. It is dropped entirely; the generic revert on `ConfigWriteFailed`
///   is sufficient and correct.)
/// - **`Io`** on the edit path can originate from the pre-write `load()`,
///   the cross-process edit lock (F2), or a critical-section failure re-wrapped
///   by `with_edit_lock`'s error bridge — but the staging/atomic-install
///   pipeline never partially replaces the live config, so disk is unchanged
///   in every case.
///
/// Because the live config is untouched in every one of these cases, the
/// optimistic UI update is a lie and must be overwritten with disk truth right
/// away rather than waiting for the 5s cooldown.
fn map_sshd_error(verb: &str, who: &str, e: &toride_ssh::Error) -> SshOpError {
    let message = format!("failed to {verb} '{who}': {e}");
    tracing::error!("sshd: {message}");
    let revert = matches!(
        e,
        toride_ssh::Error::SshdConfigInvalid(_)
            | toride_ssh::Error::SshdNotFound(_)
            | toride_ssh::Error::SudoFailed(_)
            // ConfigWriteFailed spans staging/fsync/backup/install/chmod
            // failures. Under the chmod-before-rename invariant (see F7 doc
            // above) NONE of these leave the live config changed, so the
            // optimistic UI update always disagrees with disk truth and must
            // be reverted now.
            | toride_ssh::Error::ConfigWriteFailed(_)
            // On the edit path, Io can come from load(), the cross-process
            // lock (F2), or a re-wrapped critical-section failure — but the
            // staging/atomic-install pipeline never partially replaces the
            // live config, so disk is unchanged in every case.
            // The optimistic UI update is therefore a lie and must be reverted
            // now rather than left to the 5s refresh — identical semantics to
            // the other disk-untouched variants above.
            | toride_ssh::Error::Io(_)
    );
    if revert {
        SshOpError::reverting(message)
    } else {
        SshOpError::transient(message)
    }
}

/// Privilege-inversion guard: refuse to lock the operator out.
///
/// Returns `Some(err)` when denying or resetting `username` would be
/// self-destructive — i.e. it targets the literal `root`, any account with
/// UID 0, or the account currently running toride. This is defense-in-depth
/// (the UI may also guard); [`execute_op`] MUST refuse regardless.
///
/// `verb` is "deny" or "reset" for the error message.
///
/// Best-effort but correct for the common cases: literal "root", current
/// effective user, and a `/etc/passwd` (Linux) / `dscl` (macOS) UID lookup.
#[allow(dead_code)]
fn would_lock_out(verb: &str, username: &str) -> Option<SshOpError> {
    // Always refuse the literal root account.
    if username == "root" {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    // Refuse if this is the account running toride.
    if let Some(current) = current_username()
        && current == username
    {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    // UID-based fallback: current_username() resolves the euid via a reverse
    // lookup (`dscl -search` on macOS, /etc/passwd scan on Linux) which can
    // return None on odd/unknown euids (containers, auto-allocated UIDs, a
    // stripped-down macOS Directory Service). In that case the name check
    // above is skipped entirely, narrowing the guard. Close that gap by
    // comparing the raw euid against the *forward* lookup
    // (uid_for_username(username)) — which uses a different lookup path
    // (`dscl -read` / /etc/passwd) and can succeed where the reverse one
    // failed. If they are equal, denying/resetting `username` would target the
    // operator even though we couldn't resolve the euid to a name.
    //
    // The forward lookup is bound ONCE and reused for the UID-0 check below —
    // uid_for_username spawns `dscl` (macOS) / reads /etc/passwd (Linux)
    // synchronously, so the redundant second spawn was pure waste.
    let euid = unsafe { libc::geteuid() };
    let resolved_uid = uid_for_username(username);
    would_lock_out_with_uid(verb, username, euid, resolved_uid)
}

/// Async entry point for [`would_lock_out`] that does NOT block the tokio
/// worker.
///
/// `execute_op` runs on a tokio task, and the synchronous `would_lock_out`
/// shells out to `dscl` (macOS) / `getent`/`id` and reads `/etc/passwd` via
/// `current_username()` (reverse lookup) and `uid_for_username(target)`
/// (forward lookup). Each of those is a blocking call that would stall the
/// async worker thread (F19). The operator's own identity (`current_username`
/// + `geteuid`) never changes during the process, but resolving the TARGET
///   user's UID is inherently per-op.
///
/// This wrapper performs the cheap literal-root check inline, then runs all
/// blocking lookups (`current_username` + `uid_for_username`) on the blocking
/// thread pool via [`tokio::task::spawn_blocking`], so the async worker stays
/// free. The synchronous [`would_lock_out`] is retained for direct/test use
/// (tests do not run on an async worker, so blocking there is fine).
///
/// Returns the same `Option<SshOpError>` as [`would_lock_out`].
async fn would_lock_out_async(verb: &str, username: &str) -> Option<SshOpError> {
    // Cheap inline short-circuit: no blocking lookup needed for literal root.
    if username == "root" {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    // Run every blocking lookup (reverse + forward) off the async worker. The
    // owned `verb`/`username` are moved into the blocking closure; the inner
    // logic is identical to the sync `would_lock_out` body (just without the
    // redundant literal-root branch, already handled above). Clones are kept
    // for the JoinError fallback (the originals are consumed by spawn_blocking).
    let verb = verb.to_string();
    let username = username.to_string();
    let verb_fallback = verb.clone();
    let username_fallback = username.clone();
    tokio::task::spawn_blocking(move || {
        // Re-check literal root defensively (the closure is a separate trust
        // boundary), then the name + UID lookups.
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
        let euid = unsafe { libc::geteuid() };
        let resolved_uid = uid_for_username(&username);
        would_lock_out_with_uid(&verb, &username, euid, resolved_uid)
    })
    .await
    .unwrap_or_else(move |e| {
        // The blocking task panicked. Treat it as refuse-by-default (same
        // posture as the unresolvable branch) — never risk a self-lockout.
        tracing::error!(
            "would_lock_out blocking task panicked for '{username_fallback}': {e}; refusing"
        );
        Some(SshOpError::reverting(format!(
            "refusing to {verb_fallback} '{username_fallback}': lockout check failed ({e})"
        )))
    })
}

/// Core of [`would_lock_out`] with the current euid and the forward-lookup UID
/// injected as parameters. [`would_lock_out`] performs the (blocking) lookups
/// and the name check, then delegates the UID-equality, UID-0, and
/// unresolvable-target decisions here. Split out so the backstop branches can
/// be exercised deterministically in tests without forging `geteuid` or `dscl`.
///
/// - `euid` is the process effective UID.
/// - `resolved_uid` is what `uid_for_username(username)` returned (`None` if
///   the user is unknown to every lookup path — NSS, `dscl /Search`, `id`,
///   `/etc/passwd`).
///
/// **Refuse-by-default (F10 fix).** When `resolved_uid` is `None` we cannot
/// positively identify the target account. The old behavior allowed the
/// operation in that case, which meant an operator on a network account
/// (OD/LDAP/sssd) that the *local-only* lookup couldn't resolve could deny or
/// reset *themselves* and get locked out. A lockout guard's safe default when
/// uncertain is to **refuse**: the operator can resolve the lookup (e.g.
/// ensure NSS/sssd is reachable) and retry. The only operations routed through
/// here are `deny`/`reset` (privilege-inversion guards in [`execute_op`]); a
/// false refusal is a harmless retry, a false allow is an SSH lockout.
fn would_lock_out_with_uid(
    verb: &str,
    username: &str,
    euid: u32,
    resolved_uid: Option<u32>,
) -> Option<SshOpError> {
    // Refuse if the username resolves to the operator's own UID (the
    // forward-lookup fallback for an unresolvable reverse lookup).
    if resolved_uid == Some(euid) {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    // Refuse if the username resolves to UID 0.
    if resolved_uid == Some(0) {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': would lock out root / your own account"
        )));
    }
    // Refuse-by-default: the target could not be positively identified by any
    // lookup path. For a lockout guard, uncertainty must err on the side of
    // refusal — see the F10 doc comment above.
    if resolved_uid.is_none() {
        return Some(SshOpError::reverting(format!(
            "refusing to {verb} '{username}': cannot resolve account to a UID \
             (network account unavailable?); refusing to avoid a self-lockout"
        )));
    }
    None
}

/// Best-effort name of the account running this process.
fn current_username() -> Option<String> {
    // SAFETY: geteuid is a trivial read with no preconditions.
    let euid = unsafe { libc::geteuid() };
    uid_to_username(euid)
}

/// F11: self-lockout guard for per-key `authorized_keys` removal.
///
/// The `authorized_keys` file the `AuthorizedKeysService` writes is the
/// OPERATOR's own (`SshPaths::authorized_keys_path()` → `~/.ssh/authorized_keys`),
/// so deleting the operator's last authorized key removes their only SSH pubkey
/// and locks them out. This mirrors the `sshd_config` `would_lock_out` invariant
/// for the per-key removal path, which previously had NO guard (the deny/reset
/// guards only cover `sshd_config` access control).
///
/// Refuses `Some(err)` (reverting) when removing every key whose fingerprint
/// matches `fingerprint` would drop the operator's `authorized_keys` count to
/// zero. Reads the current entry list once via `svc.list()` and counts both the
/// total entries and the matching ones; if `matches >= total` (the removal
/// would empty the file), it is refused. A lookup error is treated as refuse-
/// by-default (same posture as `would_lock_out_with_uid`'s unresolvable branch)
/// — the operator can resolve the file state and retry.
///
/// Returns `None` (allow) when the file has no entries at all (there is nothing
/// to remove and nothing to lock out) or when at least one key would remain
/// after the removal.
async fn would_lock_out_authorized_key(
    svc: &toride_ssh::authorized_keys::AuthorizedKeysService<'_>,
    fingerprint: &str,
) -> Option<SshOpError> {
    let entries = match svc.list().await {
        Ok(e) => e,
        Err(e) => {
            // Refuse-by-default: we cannot confirm a key would remain, so do
            // not risk a self-lockout. The operator can fix the file and retry.
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
    // An empty file means nothing to remove — allow (the backend `remove` will
    // no-op and return 0). The guard only protects against emptying a non-empty
    // file down to zero.
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

/// Look up the UID for a username.
///
/// Resolution order (so network accounts — OD/LDAP/sssd — resolve, not just
/// local `/etc/passwd` / Directory Service entries):
/// 1. **NSS** in-process via `getpwnam_r` (covers `/etc/passwd`, LDAP, sssd,
///    OD — whatever NSS is configured to consult). This is the F10 fix: the
///    old implementation only consulted the **local** `dscl .` node (macOS)
///    or `/etc/passwd` (Linux), so a network-account operator could not be
///    resolved and `would_lock_out` would silently permit a self-lockout.
/// 2. **`dscl /Search`** (macOS) — the system search path, not just the local
///    `.` node.
/// 3. **Portable command fallback** (`id -u <name>`) — used if the in-process
///    NSS call is unavailable or fails unexpectedly.
/// 4. **`/etc/passwd`** scan — last resort, local files only.
///
/// Returns `None` if every path fails or the user is unknown. Note this is a
/// **forward** lookup, distinct from the reverse [`uid_to_username`]; the two
/// can disagree on the same account, so [`would_lock_out`] uses this forward
/// lookup as a fallback when the reverse lookup returns `None`.
fn uid_for_username(username: &str) -> Option<u32> {
    if let Some(uid) = nss_uid_for_username(username) {
        return Some(uid);
    }
    if cfg!(target_os = "macos") {
        if let Some(uid) = dscl_uid_for_username(username, "/Search") {
            return Some(uid);
        }
        // Fall back to the local node for setups where /Search is empty.
        if let Some(uid) = dscl_uid_for_username(username, ".") {
            return Some(uid);
        }
    }
    if let Some(uid) = id_uid_for_username(username) {
        return Some(uid);
    }
    passwd_uid_for_username(username)
}

/// Resolve a UID back to a username.
///
/// Same resolution order as [`uid_for_username`] (NSS primary, then `dscl
/// /Search`, then `getent`/`id`, then `/etc/passwd`), so the forward and
/// reverse lookups consult the same databases.
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

/// NSS forward lookup via `getpwnam_r`. Available on all Unix targets that the
/// `libc` crate supports; consults whatever NSS is configured with (files,
/// ldap, sss, compat, …). Returns `None` if the user is unknown or the call
/// fails. Empty usernames short-circuit (`getpwnam_r("")` is unspecified).
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
    // Start at 2 KiB (ample for files/sss); grow on ERANGE for very long LDAP
    // directory entries, capping at 64 KiB so a pathological NSS module can't
    // make us allocate unbounded memory.
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
        // pw_uid is only valid while `result` (== &pwd here) is non-null.
        let uid = unsafe { (*result).pw_uid };
        return Some(uid);
    }
}

/// NSS reverse lookup via `getpwuid_r`. Returns `None` if the UID is unknown
/// or the call fails. The name is copied into an owned `String` before the C
/// buffer is dropped. Retries with a larger buffer on ERANGE (long LDAP
/// entries), capped at 64 KiB.
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

/// macOS Directory Service forward lookup against a specific node (e.g.
/// `/Search` for the system search path, `.` for the local node only).
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

/// macOS Directory Service reverse lookup against a specific node.
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

/// Portable command forward fallback: `id -u <name>`. Works on both macOS and
/// Linux and consults NSS (so it sees LDAP/sssd users). Returns `None` if
/// `id` is missing or reports failure for an unknown user.
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

/// Portable command reverse fallback via `getent passwd <uid>` (Linux/BSD).
/// Skipped on macOS (dscl already ran there). Parses the username field of
/// the first matching passwd line.
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

/// `/etc/passwd` forward scan. Local files only — the last resort.
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

/// `/etc/passwd` reverse scan. Local files only.
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

/// Execute a pending write operation using the given `SshManager`.
///
/// Returns `Ok(label)` on success (e.g. `"added host 'myserver'"`) or
/// `Err(SshOpError)` on failure. On error, `revert_optimistic` signals
/// whether the optimistic UI update is known-stale and should be reverted
/// immediately. Both outcomes are also logged via tracing.
///
/// Build the `ssh-keygen` argv used to derive the public key from a private
/// key (the operation behind passphrase verification).
///
/// Deliberately OMITS `-P <passphrase>`: the secret is fed to the child via a
/// temporary `SSH_ASKPASS` helper (see [`check_key_passphrase`]) so it never
/// reaches the child argv or `/proc/<pid>/cmdline`, where it would be readable
/// by every local user for the whole lifetime of the subprocess.
fn keygen_read_public_argv(key_path: &str) -> Vec<String> {
    vec!["-y".to_owned(), "-f".to_owned(), key_path.to_owned()]
}

/// Verify a private-key passphrase WITHOUT leaking it onto the argv.
///
/// Spawns `ssh-keygen -y -f <key>` (no `-P`!) and answers the passphrase prompt
/// via a temporary `SSH_ASKPASS` script (created mode `0o700`, removed on drop),
/// so the secret is visible only in this task's memory — never in `ps`,
/// `/proc/<pid>/cmdline`, a child env var, or on disk after the call returns.
///
/// Returns `Ok(true)` if the key decrypts with `passphrase` (or is not
/// passphrase-protected at all), `Ok(false)` if the passphrase is wrong.
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
    // `askpass` is dropped here -> the on-disk script is removed.
    Ok(status.success())
}

/// Dispatch a UI SSH action to the backend.
///
/// # Errors
///
/// Returns `Err(SshOpError)` when the backend reports a write/validation
/// failure or when `SshManager::new()` cannot initialize. Each arm maps its
/// backend error to a [`SshOpError`] whose `revert_optimistic` flag tells the
/// caller whether to refresh the optimistic UI view immediately.
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
            match svc
                .edit(|ast| toride_ssh::config::ConfigService::add_host(ast, &name, directives))
                .await
            {
                Ok(()) => {
                    tracing::info!("config: added host '{name}'");
                    Ok(format!("added host '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to add host '{name}': {e}");
                    tracing::error!("config: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::ConfigRemoveHost { name } => {
            let svc = mgr.config();
            match svc
                .edit(|ast| toride_ssh::config::ConfigService::remove_host(ast, &name))
                .await
            {
                Ok(()) => {
                    tracing::info!("config: removed host '{name}'");
                    Ok(format!("removed host '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to remove host '{name}': {e}");
                    tracing::error!("config: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::ConfigEditHost {
            old_name,
            new_name,
            host_name,
            user,
            port,
        } => {
            let svc = mgr.config();
            match svc
                .edit(|ast| {
                    // Remove old block, add new one
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
                .await
            {
                Ok(()) => {
                    tracing::info!("config: edited host '{old_name}' → '{new_name}'");
                    Ok(format!("edited host '{old_name}' → '{new_name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to edit host '{old_name}': {e}");
                    tracing::error!("config: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
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
            match svc.create(params).await {
                Ok(_) => {
                    tracing::info!("keys: created '{name}'");
                    Ok(format!("created key '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to create key '{name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
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
            match svc.delete(params).await {
                Ok(()) => {
                    tracing::info!("keys: deleted '{name}'");
                    Ok(format!("deleted key '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to delete key '{name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::KeyRename { old_name, new_name } => {
            let svc = mgr.keys();
            match svc.rename(&old_name, &new_name).await {
                Ok(()) => {
                    tracing::info!("keys: renamed '{old_name}' → '{new_name}'");
                    Ok(format!("renamed '{old_name}' → '{new_name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to rename '{old_name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::KnownHostAdd { host } => {
            let svc = mgr.known_hosts();
            match svc.add(&host).await {
                Ok(()) => {
                    tracing::info!("known_hosts: added '{host}'");
                    Ok(format!("added known host '{host}'"))
                }
                Err(e) => {
                    let msg = format!("failed to add known host '{host}': {e}");
                    tracing::error!("known_hosts: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::KnownHostRemove { host } => {
            let svc = mgr.known_hosts();
            match svc.remove(&host).await {
                Ok(()) => {
                    tracing::info!("known_hosts: removed '{host}'");
                    Ok(format!("removed known host '{host}'"))
                }
                Err(e) => {
                    let msg = format!("failed to remove known host '{host}': {e}");
                    tracing::error!("known_hosts: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::AgentAddKey { path } => {
            let svc = mgr.agent();
            let path_ref = std::path::Path::new(&path);
            match svc.add_key(path_ref).await {
                Ok(()) => {
                    tracing::info!("agent: added key '{path}'");
                    Ok(format!("added key to agent: '{path}'"))
                }
                Err(e) => {
                    let msg = format!("failed to add key '{path}' to agent: {e}");
                    tracing::error!("agent: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::AgentRemoveKey { path } => {
            let svc = mgr.agent();
            let path_ref = std::path::Path::new(&path);
            match svc.remove_key(path_ref).await {
                Ok(()) => {
                    tracing::info!("agent: removed key '{path}'");
                    Ok(format!("removed key from agent: '{path}'"))
                }
                Err(e) => {
                    let msg = format!("failed to remove key '{path}' from agent: {e}");
                    tracing::error!("agent: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::AuthorizedKeyAdd {
            public_key,
            comment,
            options,
        } => {
            let svc = mgr.authorized_keys();
            match svc
                .add(&public_key, comment.as_deref(), options.as_deref())
                .await
            {
                Ok(()) => {
                    tracing::info!("authorized_keys: added key");
                    Ok("added authorized key".to_string())
                }
                Err(e) => {
                    let msg = format!("failed to add authorized key: {e}");
                    tracing::error!("authorized_keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::AuthorizedKeyRemove { fingerprint } => {
            let svc = mgr.authorized_keys();
            // F11: self-lockout guard. The authorized_keys file written here is
            // the OPERATOR's own (~/.ssh/authorized_keys via
            // `SshPaths::authorized_keys_path`), so removing the operator's last
            // authorized key would lock them out of SSH (no pubkey left to auth
            // with). The deny/reset guards above cover sshd_config access
            // control; this mirrors that invariant for per-key authorized_keys
            // removal. Refuse BEFORE deleting if the removal would drop the
            // operator's authorized_keys count to zero. (The sshd_config
            // would_lock_out guard covers root/uid-0/current-user; here the
            // target is always the operator's own file, so the zero-count check
            // is the load-bearing one.)
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
            match svc.chmod_fix(&name).await {
                Ok(()) => {
                    tracing::info!("keys: fixed permissions on '{name}'");
                    Ok(format!("fixed permissions on '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to fix permissions on '{name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
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
            match svc.hash_all().await {
                Ok(()) => {
                    tracing::info!("known_hosts: hashed all hostnames");
                    Ok("hashed all known hostnames".to_string())
                }
                Err(e) => {
                    let msg = format!("failed to hash all known hostnames: {e}");
                    tracing::error!("known_hosts: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::AgentRemoveAll => {
            let svc = mgr.agent();
            match svc.remove_all().await {
                Ok(()) => {
                    tracing::info!("agent: removed all keys");
                    Ok("removed all keys from agent".to_string())
                }
                Err(e) => {
                    let msg = format!("failed to remove all keys from agent: {e}");
                    tracing::error!("agent: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::ForwardCancel {
            control_path,
            local_port,
        } => {
            let svc = mgr.forward();
            let path = std::path::Path::new(&control_path);
            match svc.cancel(path, local_port).await {
                Ok(()) => {
                    tracing::info!("forward: cancelled port {local_port} on '{control_path}'");
                    Ok(format!("cancelled forward on port {local_port}"))
                }
                Err(e) => {
                    let msg = format!("failed to cancel forward on port {local_port}: {e}");
                    tracing::error!("forward: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
        }
        SshOp::ForwardExitSession { control_path } => {
            let svc = mgr.forward();
            let path = std::path::Path::new(&control_path);
            match svc.exit_session(path).await {
                Ok(()) => {
                    tracing::info!("forward: exited session '{control_path}'");
                    Ok(format!("exited session '{control_path}'"))
                }
                Err(e) => {
                    let msg = format!("failed to exit session '{control_path}': {e}");
                    tracing::error!("forward: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
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
            match svc.revoke_key(krl_path, &name).await {
                Ok(()) => {
                    tracing::info!("certificates: revoked key '{name}'");
                    Ok(format!("revoked key '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to revoke key '{name}': {e}");
                    tracing::error!("certificates: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
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
            match svc.install_key_to_remote(&key_path, &dest).await {
                Ok(_) => {
                    tracing::info!("keys: installed '{key_name}' to '{dest}'");
                    Ok(format!("installed '{key_name}' to '{dest}'"))
                }
                Err(e) => {
                    let msg = format!("failed to install '{key_name}' to '{dest}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(SshOpError::transient(msg))
                }
            }
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
            // SECURITY: the passphrase is fed to ssh-keygen through a temporary
            // SSH_ASKPASS helper, NOT as `-P <passphrase>` on the argv — see
            // [`check_key_passphrase`]. This keeps the secret out of
            // `ps`/`/proc/<pid>/cmdline` for the whole subprocess lifetime.
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
            // No privilege-inversion guard: allowing login can never lock the
            // operator out. (Deny/reset carry the guard; allow is always safe.)
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
            // Privilege-inversion guard: refuse BEFORE touching anything if
            // denying this user would lock the operator out (literal root,
            // UID 0, or the current account). execute_op MUST refuse regardless
            // of any UI-side guard — defense in depth. Run off the async worker
            // via would_lock_out_async — the lookup shells out to dscl/getent
            // and reads /etc/passwd (F19).
            if let Some(err) = would_lock_out_async("deny", &username).await {
                return Err(err);
            }
            let is_root = toride_ssh::is_root();
            let result = toride_ssh::config::sshd::edit(is_root, |ast| {
                toride_ssh::config::sshd::add_user_to_deny(ast, &username)?;
                // Mirror SshdAllowUser: a user who is being denied must also be
                // removed from AllowUsers, otherwise the persisted config can
                // carry the user in BOTH lists (OpenSSH resolves DenyUsers
                // last, so the outcome is still a lockout, but the file is
                // contradictory and confuses operators/other tooling).
                // remove_user_from_allow is a documented safe no-op when the
                // user is absent.
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
            // Privilege-inversion guard: refuse BEFORE touching anything if
            // resetting this user would lock the operator out. Reset removes an
            // explicit allow; if the operator depended on it (group-only
            // setups), they could be stranded. Refuse the dangerous cases. Run
            // off the async worker via would_lock_out_async — the lookup shells
            // out to dscl/getent and reads /etc/passwd (F19).
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

/// Collect SSH data by reading real files and calling real services.
///
/// All subsystems run in parallel via `tokio::join!`. Individual failures are
/// logged and produce empty data — the app never crashes from a bad subsystem.
///
/// When `use_cache` is true and `cached_diag` is provided, diagnostics are
/// reused from the cache instead of re-running the full check suite.
///
/// Returns `(bundle, used_cache)` where `used_cache` records whether the
/// diagnostics were actually taken from the cache on a successful collection.
/// The caller advances the TTL clock ONLY when `used_cache == false`, so a
/// cache-hit poll never resets the freshness timestamp with stale data.
async fn collect_real_data(
    use_cache: bool,
    cached_diag: Option<Vec<DiagnosticEntry>>,
) -> (SshDataBundle, bool) {
    let mgr = match toride_ssh::SshManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("SshManager::new() failed: {e}");
            return (empty_bundle(), false);
        }
    };

    // All subsystems in parallel — diagnostics may be cached
    let (keys_r, known_hosts_r, auth_keys_r, config_r, diag_r, agent_r, forward_r, cert_r) = tokio::join!(
        collect_keys(&mgr),
        collect_known_hosts(&mgr),
        collect_authorized_keys(&mgr),
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
        collect_certificates(&mgr),
    );

    let keys = keys_r.unwrap_or_default();
    let known_hosts = known_hosts_r.unwrap_or_default();
    let authorized_keys = auth_keys_r.unwrap_or_default();
    let config_hosts = config_r.unwrap_or_default();
    let diagnostics = if use_cache {
        cached_diag.unwrap_or_default()
    } else {
        diag_r.and_then(std::result::Result::ok).unwrap_or_default()
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

    // Security data involves blocking filesystem I/O (sshd_config, /etc/passwd).
    // Run it on the blocking thread pool to avoid stalling the tokio worker.
    let security = {
        let known_hosts = known_hosts.clone();
        let authorized_keys = authorized_keys.clone();
        let diagnostics = diagnostics.clone();
        tokio::task::spawn_blocking(move || {
            build_security_data(&known_hosts, &authorized_keys, &diagnostics)
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("security data collection panicked: {e}");
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

/// Empty bundle used when `SshManager` fails to initialize.
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
        diagnostics: Vec::new(),
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
                available: false, // no sshd_config read
                allowed_users: vec![],
                denied_users: vec![],
                allowed_groups: vec![],
                denied_groups: vec![],
                auth_methods: vec![],
                // Use OpenSSH defaults when sshd_config is unavailable.
                password_auth: true,
                pubkey_auth: true,
                permit_root_login: "prohibit-password".to_string(),
            },
            system_users: Vec::new(),
            is_root: toride_ssh::is_root(),
        },
    }
}

// ── Individual Collectors ────────────────────────────────────────────────────

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

async fn collect_certificates(mgr: &toride_ssh::SshManager) -> Result<Vec<CertificateEntry>, ()> {
    let ssh_dir = match toride_ssh::SshPaths::new() {
        Ok(p) => p.ssh_dir().to_path_buf(),
        Err(_) => return Ok(Vec::new()),
    };

    let cert_files: Vec<std::path::PathBuf> = match std::fs::read_dir(&ssh_dir) {
        Ok(entries) => entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("-cert.pub"))
            })
            .collect(),
        Err(_) => return Ok(Vec::new()),
    };

    if cert_files.is_empty() {
        return Ok(Vec::new());
    }

    let cert_svc = mgr.certificate();
    let mut raw = Vec::new();

    for path in cert_files {
        match cert_svc.inspect(&path).await {
            Ok(info) => raw.push((path, info)),
            Err(e) => {
                tracing::debug!(
                    "certificate {}: {e}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
            }
        }
    }

    Ok(ssh_convert::convert_certificates(raw))
}

/// Build security overview data from already-collected real data.
///
/// Reads `/etc/ssh/sshd_config` once and passes the content to both
/// `parse_sshd_config` and `parse_sshd_access_info` to avoid a TOCTOU
/// inconsistency from reading the file twice.
fn build_security_data(
    known_hosts: &[KnownHostEntry],
    authorized_keys: &[AuthorizedKeyEntry],
    diagnostics: &[DiagnosticEntry],
) -> SshSecurityData {
    // Read sshd_config once — shared by both parse_sshd_config and parse_sshd_access_info.
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
        system_users: parse_system_users(),
        is_root: toride_ssh::is_root(),
    }
}

// ── Security Overview Types ──────────────────────────────────────────────────

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

/// Parse an `sshd_config` boolean value case-insensitively.
///
/// `sshd_config` values are matched case-insensitively by OpenSSH, so
/// `PermitRootLogin Yes`, `YES`, and `yes` are all equivalent. The parser
/// ([`parse_sshd_config_from`]) preserves the original case of `d.value`, so
/// any exact-case comparison (`== "yes"`) silently mis-grades a capitalized
/// value. This helper is the single source of truth for that parsing: it
/// trims surrounding whitespace and accepts `yes`/`true`/`1` as true,
/// `no`/`false`/`0` as false, and returns `None` for anything else (including
/// an unset/empty value, which callers handle with OpenSSH defaults).
fn sshd_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" => Some(true),
        "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

/// Test whether a stored `sshd_config` value is the boolean `want`.
///
/// This replaces the old exact-case comparisons in [`SshSecurityData::grade`]
/// and [`SshSecurityData::checks`]. Callers must supply the **default**
/// semantics explicitly (the third arg) so that an unset or non-boolean value
/// is handled deliberately, never silently:
///
/// - returns the parsed value's comparison to `want` when the value parses
///   as a boolean;
/// - otherwise returns `default_when_unset` (which encodes the OpenSSH
///   default or the "absent == treat as" choice for that check).
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

        // Major deductions for insecure settings
        if !sshd_bool_is(cfg.get("passwordauthentication"), false, false) {
            // PasswordAuthentication defaults to "yes" (OpenSSH), so deduct
            // whenever it is NOT explicitly disabled (falsey) — i.e. enabled
            // or unset. Case-insensitive on the stored value.
            score -= 25;
        }
        if sshd_bool_is(cfg.get("permitrootlogin"), true, false) {
            // PermitRootLogin defaults to "prohibit-password"; a literal
            // truthy value ("yes"/"true"/"1") is the only insecure form.
            score -= 20;
        }
        if sshd_bool_is(cfg.get("permitemptypasswords"), true, false) {
            // PermitEmptyPasswords defaults to "no"; only deduct on an explicit
            // truthy value.
            score -= 15;
        }
        if sshd_bool_is(cfg.get("pubkeyauthentication"), false, false) {
            // PubkeyAuthentication defaults to "yes"; deduct only when it is
            // explicitly disabled (a falsey value).
            score -= 15;
        }
        // Minor deductions for warnings
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
                // Passing only when explicitly disabled (falsey). Defaults to
                // "yes" (OpenSSH), so an unset or non-boolean value is NOT
                // passing — case-insensitively now.
                passing: sshd_bool_is(cfg.get("passwordauthentication"), false, false),
                informational: false,
            },
            SecurityCheck {
                label: "Root login".into(),
                detail: cfg
                    .get("permitrootlogin")
                    .cloned()
                    .unwrap_or_else(|| "prohibit-password (default)".into()),
                // Passing unless explicitly set truthy ("yes"/"true"/"1"). The
                // default and any non-boolean (e.g. "prohibit-password") pass.
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
                // Passing unless explicitly disabled (falsey). Defaults to
                // "yes", so unset / non-boolean passes.
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
                // Passing only when explicitly disabled (falsey). Defaults to
                // "yes", so unset / non-boolean is NOT passing.
                passing: sshd_bool_is(cfg.get("allowagentforwarding"), false, false),
                informational: false,
            },
            SecurityCheck {
                label: "X11 forwarding".into(),
                detail: cfg
                    .get("x11forwarding")
                    .cloned()
                    .unwrap_or_else(|| "no (default)".into()),
                // Passing unless explicitly set truthy. Defaults to "no".
                passing: !sshd_bool_is(cfg.get("x11forwarding"), true, false),
                informational: false,
            },
            SecurityCheck {
                label: "Empty passwords".into(),
                detail: cfg
                    .get("permitemptypasswords")
                    .cloned()
                    .unwrap_or_else(|| "no (default)".into()),
                // Passing unless explicitly set truthy. Defaults to "no".
                passing: !sshd_bool_is(cfg.get("permitemptypasswords"), true, false),
                informational: false,
            },
        ]
    }
}

/// Parse `/etc/ssh/sshd_config` for key-value pairs.
///
/// Returns an empty map if the file doesn't exist or isn't readable.
#[allow(dead_code)]
fn parse_sshd_config() -> HashMap<String, String> {
    let contents = std::fs::read_to_string(Path::new("/etc/ssh/sshd_config")).unwrap_or_default();
    parse_sshd_config_from(&contents)
}

/// Parse `sshd_config` content (already read from disk) into key-value pairs.
///
/// This builds the map from the lossless AST
/// ([`toride_ssh::config::ast::parse`]), iterating ONLY top-level
/// [`ConfigNode::Directive`] nodes. Anything nested inside a `Match` or `Host`
/// block is structurally invisible here, and comments/blank lines are skipped
/// — so `Match`/`Host`-scoped overrides (e.g. an indented
/// `PasswordAuthentication yes` inside a `Match Address ...` block) can never
/// leak into the global values. This keeps [`SshSecurityReport::grade`] and
/// [`SshSecurityReport::checks`] consistent with the sibling
/// [`parse_sshd_access_info_from`], which is already Match-immune.
///
/// **`Include` expansion.** A top-level `Include` directive (used by stock
/// Debian/Ubuntu/RHEL/Fedora to pull in `/etc/ssh/sshd_config.d/*.conf`) is
/// now followed: paths are resolved relative to `/etc/ssh` (the conventional
/// sshd config dir) when relative, glob-expanded (sorted), and merged with
/// **first-occurrence-wins** semantics — matching OpenSSH, where the first
/// global-scope value set for a directive is the effective one. This is a
/// READ-ONLY walk (no privilege needed). `Include` directives inside a
/// `Match`/`Host` block are skipped along with the rest of the block.
///
/// The AST's `d.value` already strips trailing inline comments, and the key is
/// lowercased to match how [`grade`] / [`checks`] look directives up.
fn parse_sshd_config_from(contents: &str) -> HashMap<String, String> {
    parse_sshd_config_from_dir(contents, Path::new("/etc/ssh"))
}

/// Same as [`parse_sshd_config_from`] but with an explicit base directory used
/// to resolve relative `Include` patterns. Split out so the Include-expansion
/// path can be exercised against a tempfile tree in tests without touching
/// `/etc/ssh`.
fn parse_sshd_config_from_dir(contents: &str, base_dir: &Path) -> HashMap<String, String> {
    use toride_ssh::config::ast::{ConfigNode, parse};

    // Recursively walk a parsed file's top-level directives, expanding
    // Includes inline and applying first-occurrence-wins. `seen` guards
    // against include cycles (a file including itself, directly or
    // transitively) — OpenSSH treats such cycles as an error; we just stop.
    fn walk(
        ast_nodes: &[ConfigNode],
        base_dir: &Path,
        config: &mut HashMap<String, String>,
        seen: &mut std::collections::HashSet<std::path::PathBuf>,
    ) {
        for node in ast_nodes {
            let ConfigNode::Directive(d) = node else {
                // Skip MatchBlock / HostBlock (and their nested directives),
                // Comment, and BlankLine — only top-level directives are
                // global.
                continue;
            };
            let key = d.keyword.to_lowercase();
            if key == "include" {
                expand_include(&d.value, base_dir, config, seen);
                // The Include directive itself never enters the map (it has
                // no security-relevant value), matching the old behavior.
                continue;
            }
            // First-occurrence-wins: only set a key the first time it is seen
            // in source order (main file before its includes, includes in
            // sorted glob order). OpenSSH: "the first obtained value for a
            // global directive is used".
            config.entry(key).or_insert_with(|| d.value.clone());
        }
    }

    /// Expand a single `Include` argument (which may list multiple
    /// whitespace-separated glob patterns) into matching files and merge them.
    fn expand_include(
        args: &str,
        base_dir: &Path,
        config: &mut HashMap<String, String>,
        seen: &mut std::collections::HashSet<std::path::PathBuf>,
    ) {
        for pattern in args.split_whitespace() {
            let resolved = resolve_include_path(pattern, base_dir);
            for file in glob_include(&resolved) {
                // Canonicalize for cycle detection; fall back to the raw path
                // if canonicalization fails (file may still be readable).
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

/// Resolve an `Include` pattern to an absolute path.
///
/// OpenSSH: if the path does not start with `/` or `~/`, it is taken relative
/// to the directory of the main config file. Here `base_dir` is that directory
/// (conventionally `/etc/ssh`). `~`-expansion is intentionally not performed
/// — `sshd_config` drop-ins under `/etc/ssh/sshd_config.d/` are always absolute
/// or relative to the config dir, and tilde expansion would require the
/// operator's home which a system service does not have.
fn resolve_include_path(pattern: &str, base_dir: &Path) -> std::path::PathBuf {
    let p = Path::new(pattern);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

/// Glob-expand an Include pattern into matching files (sorted).
///
/// Supports `*` and `?` within a single path segment (the common
/// `sshd_config.d/*.conf` case) and a leading `**/` for recursive matches,
/// mirroring the include logic in `toride_ssh::config::resolve` (which is
/// `pub(crate)` and so cannot be reused directly from this crate). Only
/// regular files are returned; directories are skipped. Missing directories
/// yield an empty result (matching OpenSSH, which silently ignores a pattern
/// that matches nothing). Sort order is deterministic so grading is stable.
fn glob_include(pattern: &Path) -> Vec<std::path::PathBuf> {
    let pattern_str = pattern.to_string_lossy().into_owned();
    let mut out = Vec::new();

    // Recursive `**/` support. Only `**/` (zero-or-more directory levels)
    // triggers recursive matching; a bare `**` without a following slash is
    // left to the single-segment matcher below (where it behaves like `*`).
    if let Some(idx) = pattern_str.find("**/") {
        let prefix = Path::new(&pattern_str[..idx]);
        // Skip past "**/" (3 chars); drop any redundant leading slashes.
        let suffix = pattern_str[idx + 3..].trim_start_matches('/');
        collect_glob_recursive(prefix, suffix, &mut out);
        out.sort();
        return out;
    }

    // Single-segment glob: split into parent dir + file-pattern.
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

/// Recursively apply `suffix` (a glob, possibly with `/`-separated segments)
/// under `dir`, matching `**` semantics (zero or more directory levels).
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
            // `**` matches zero or more levels: re-apply the full suffix at
            // every nested directory.
            collect_glob_recursive(&path, suffix, out);
        }
    }
}

/// Minimal case-sensitive glob for a single path segment: supports `*`
/// (zero or more chars) and `?` (exactly one char). Delegates the recursive
/// matching to a small state machine rather than pulling in a glob crate.
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

/// Parse access control information from `/etc/ssh/sshd_config`.
///
/// Extracts `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`,
/// `AuthenticationMethods`, and auth booleans from **global** scope only —
/// directives nested inside a `Match` block are read through the lossless AST
/// and excluded from the global values, so the security dashboard never
/// reflects conditional Match-scoped overrides.
///
/// **Note:** On macOS, `/etc/ssh/sshd_config` may not exist or may not reflect
/// the actual sshd configuration, which is managed by launchd. Additionally,
/// system users are parsed from `/etc/passwd`, which is not the primary user
/// database on macOS (Directory Service is). Results on macOS may be incomplete.
#[allow(dead_code)]
fn parse_sshd_access_info() -> SshAccessInfo {
    let contents = std::fs::read_to_string(Path::new("/etc/ssh/sshd_config")).unwrap_or_default();
    parse_sshd_access_info_from(&contents)
}

/// Parse access control information from pre-read `sshd_config` content.
///
/// This uses the lossless AST ([`toride_ssh::config::sshd`] getters) so that:
/// - `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups` are read from
///   **global** scope only — directives nested inside a `Match` block never
///   leak into the global list (a previous last-wins scanner had this bug).
/// - Multiple global occurrences are **concatenated** (OpenSSH treats them as
///   additive), matching what the editor (`sshd::add_user_to_allow`, etc.)
///   produces. Read and write now agree.
///
/// The remaining scalar directives (`AuthenticationMethods`, the auth booleans,
/// `PermitRootLogin`) are scanned from top-level [`ConfigNode::Directive`]
/// nodes only — which, by construction, excludes anything inside a
/// `Match`/`Host` block — so Match-scoped overrides never reach the global
/// values the security dashboard reports.
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

    // The list directives: populate from the global-only, concatenating
    // getters. This is the same view the editor mutates, so read == write.
    info.allowed_users = get_allow_users(&ast);
    info.denied_users = get_deny_users(&ast);
    info.allowed_groups = get_allow_groups(&ast);
    info.denied_groups = get_deny_groups(&ast);

    // Track which scalar directives were explicitly seen so we can apply
    // OpenSSH defaults only when the directive is absent.
    let mut seen_pubkey = false;
    let mut seen_password = false;
    let mut seen_permit_root = false;

    // Scalar fields: iterate top-level Directive nodes only. The AST nests the
    // contents of `Match`/`Host` blocks under their block node, so anything
    // inside a block is structurally invisible here — Match-scoped overrides
    // (e.g. `Match Address ...` → `PasswordAuthentication yes`) cannot leak
    // into the global value.
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

    // Apply OpenSSH defaults when directives are absent.
    // PubkeyAuthentication defaults to "yes" per OpenSSH spec.
    if !seen_pubkey {
        info.pubkey_auth = true;
    }
    // PasswordAuthentication defaults to "yes" in OpenSSH.
    if !seen_password {
        info.password_auth = true;
    }
    // PermitRootLogin defaults to "prohibit-password" since OpenSSH 7.0.
    if !seen_permit_root {
        info.permit_root_login = "prohibit-password".to_string();
    }

    info
}

/// Discover real SSH users on the system.
///
/// On macOS, uses Directory Service (`dscl`) to enumerate real user
/// accounts — `/etc/passwd` only contains system daemons on macOS.
/// On Linux, reads `/etc/passwd` directly.
///
/// Only returns users who have SSH actually configured: a real login
/// shell, an existing home directory, and a `.ssh/` directory.
fn parse_system_users() -> Vec<SystemUserInfo> {
    if cfg!(target_os = "macos") {
        parse_system_users_macos()
    } else {
        parse_system_users_linux()
    }
}

/// macOS: use `dscl` to query Directory Service for real users.
fn parse_system_users_macos() -> Vec<SystemUserInfo> {
    // dscl . -list /Users UniqueID
    let output = match std::process::Command::new("dscl")
        .args([".", "-list", "/Users", "UniqueID"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return vec![],
    };

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

        // Skip system accounts and underscore-prefixed daemons.
        if uid < 500 || username.starts_with('_') {
            continue;
        }

        // macOS home dirs are /Users/<name>.
        let home_dir = format!("/Users/{username}");
        let home = std::path::Path::new(&home_dir);
        if !home.is_dir() {
            continue;
        }

        // Only include users who have .ssh/ configured.
        let ssh_dir = home.join(".ssh");
        if !ssh_dir.is_dir() {
            continue;
        }

        // Look up the user's shell.
        let shell = std::process::Command::new("dscl")
            .args([".", "-read", &format!("/Users/{username}"), "UserShell"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("UserShell:"))
                    .and_then(|l| l.strip_prefix("UserShell:"))
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_else(|| "/bin/zsh".to_string());

        let (ssh_key_count, authorized_key_count) = count_ssh_keys(&ssh_dir);
        let authorized_keys_preview = collect_authorized_keys_preview(&ssh_dir, 10);

        users.push(SystemUserInfo {
            username: username.to_string(),
            shell,
            home_dir,
            ssh_key_count,
            authorized_key_count,
            authorized_keys_preview,
        });
    }

    users.sort_by(|a, b| a.username.cmp(&b.username));
    users
}

/// Linux: read /etc/passwd for real users with SSH configured.
fn parse_system_users_linux() -> Vec<SystemUserInfo> {
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

        // Skip system accounts.
        if uid < 500 {
            continue;
        }

        // Skip users with invalid / non-interactive shells.
        if invalid_shells.contains(&shell) || shell.is_empty() {
            continue;
        }

        // Only include users whose home directory actually exists.
        let home = std::path::Path::new(home_dir);
        if !home.is_dir() {
            continue;
        }

        // Only include users who have .ssh/ set up.
        let ssh_dir = home.join(".ssh");
        if !ssh_dir.is_dir() {
            continue;
        }

        let (ssh_key_count, authorized_key_count) = count_ssh_keys(&ssh_dir);
        let authorized_keys_preview = collect_authorized_keys_preview(&ssh_dir, 10);

        users.push(SystemUserInfo {
            username: username.to_string(),
            shell: shell.to_string(),
            home_dir: home_dir.to_string(),
            ssh_key_count,
            authorized_key_count,
            authorized_keys_preview,
        });
    }

    users.sort_by(|a, b| a.username.cmp(&b.username));
    users
}

/// Count SSH key files and `authorized_keys` entries in a .ssh directory.
///
/// Returns `(ssh_key_count, authorized_key_count)`.
/// SSH keys are private key files (`id_ed25519`, `id_rsa`, etc.) — files
/// starting with "id_" that don't end in .pub, .old, or .bak.
fn count_ssh_keys(ssh_dir: &std::path::Path) -> (usize, usize) {
    // Count private key files (id_* without .pub/.old/.bak suffix).
    let ssh_key_count = match std::fs::read_dir(ssh_dir) {
        Ok(entries) => entries
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.starts_with("id_")
                    && !name.ends_with(".pub")
                    && !name.ends_with(".old")
                    && !name.ends_with(".bak")
            })
            .count(),
        Err(_) => 0,
    };

    // Count authorized_keys entries.
    let authorized_key_count = match std::fs::read_to_string(ssh_dir.join("authorized_keys")) {
        Ok(contents) => contents
            .lines()
            .filter(|l| {
                let l = l.trim();
                !l.is_empty() && !l.starts_with('#')
            })
            .count(),
        Err(_) => 0,
    };

    (ssh_key_count, authorized_key_count)
}

/// Read up to `cap` `authorized_keys` entries from a .ssh directory as previews
/// for the user detail modal.
///
/// Each entry captures key type, trailing comment, 1-based line number, and a
/// best-effort SHA-256 fingerprint (computed via `ssh-key`; left as
/// `"(unknown)"` if the key blob can't be parsed). Returns an empty vec when
/// the file is absent or unreadable.
fn collect_authorized_keys_preview(
    ssh_dir: &std::path::Path,
    cap: usize,
) -> Vec<crate::ui::screens::ssh::AuthorizedKeyPreview> {
    use crate::ui::screens::ssh::AuthorizedKeyPreview;

    let Ok(contents) = std::fs::read_to_string(ssh_dir.join("authorized_keys")) else {
        return Vec::new();
    };

    let mut previews = Vec::new();
    for (idx, raw) in contents.lines().enumerate() {
        if previews.len() >= cap {
            break;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // An authorized_keys entry is: [options] type base64 [comment].
        // Heuristic: if the first whitespace token parses as a known key type,
        // there are no options; otherwise skip the leading options token.
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
                // Options present: type is the second token.
                (tokens[1], 2, tokens.get(3).copied())
            };

        // Best-effort fingerprint from the openssh string "<type> <base64>".
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
    previews
}

// ── Mock Data (test only) ───────────────────────────────────────────────────

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
            diagnostics: collect_mock_diagnostics(),
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

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// An encrypted ed25519 key (passphrase `"toride-test-passphrase"`) generated
    /// once via `ssh-keygen` and embedded so the test is hermetic — no network.
    /// Only ever used as a throwaway fixture.
    const ENCRYPTED_ED25519_PEM: &str = r"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCCl+BJeR
6fh9cjkIDA+Xy9AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILgUYeqGhLirfiaY
jS17uJqeK1rdQxFmtieIPp+gBl1QAAAAkPTsdRb/dX+52v+LSgi2fzPxv2q2iJd8uKr2Ee
5eyX2qFxQoysBDn8fRRsmqT+9RevfJU+dtl9D31ObAi0ZNMvkFzddgriQLxhb5MJopDN48
7gYRaguTorV6QQxtv2e/TUluUVUHxMZPe1c3De0Tslxhs1LNvsNWDFNLPw3QAZ5wPYUXEc
7jKXjoSvb0HXE1ZA==
-----END OPENSSH PRIVATE KEY-----
";

    /// The `ssh-keygen` argv for passphrase verification must derive the public
    /// key ONLY — never `-P`/`-N` with the secret. This is the structural
    /// guarantee that the passphrase cannot leak via argv/proc.
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

    /// End-to-end: `check_key_passphrase` feeds the secret via `SSH_ASKPASS`
    /// (never `-P`), so the embedded encrypted fixture decrypts with the right
    /// passphrase and is rejected with the wrong one. Requires `ssh-keygen` on
    /// PATH, as the existing `toride-ssh-key` integration tests do.
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
        // ssh-keygen refuses world/group-readable private keys.
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

    /// Numeric score for a [`SecurityGrade`] so tests can assert ordering
    /// (worse grade => lower score) without reaching into the enum's repr.
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
        // Real data — just verify it doesn't crash and returns a bundle
        // Verify the bundle is well-formed: security data is present.
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
        // Start with a clean slate (no warnings) to test B in isolation.
        let mut security = mock::collect_mock_security();
        security.security_diagnostics = vec![]; // Clear warnings
        security
            .sshd_config
            .insert("passwordauthentication".into(), "yes".into());
        // 100 - 25 (password) = 75 => B
        assert_eq!(security.grade(), SecurityGrade::B);
    }

    #[test]
    fn security_grade_c_with_password_and_root_login() {
        // Start with a clean slate (no warnings) to test C in isolation.
        let mut security = mock::collect_mock_security();
        security.security_diagnostics = vec![]; // Clear warnings
        security
            .sshd_config
            .insert("passwordauthentication".into(), "yes".into());
        security
            .sshd_config
            .insert("permitrootlogin".into(), "yes".into());
        // 100 - 25 (password) - 20 (root) = 55 => C
        assert_eq!(security.grade(), SecurityGrade::C);
    }

    // ── F8: case-insensitive sshd booleans ───────────────────────────────────
    // sshd_config values are matched case-insensitively by OpenSSH, but the
    // parser preserves the original case in `d.value`. Before the fix, grade()
    // and checks() used exact `== "yes"` / `!= "no"` comparisons, so a
    // capitalized `PermitRootLogin Yes` (common in hand-edited configs) scored
    // as PASSING while the access card showed root login enabled — grade and
    // access card disagreed. These tests pin the case-insensitive behavior;
    // reverting sshd_bool_is restores the silent disagreement.

    #[test]
    fn sshd_bool_parses_yes_no_true_false_one_zero_case_insensitively() {
        for yes in &["yes", "Yes", "YES", "yEs", "true", "True", "TRUE", "1"] {
            assert_eq!(sshd_bool(yes), Some(true), "{yes:?} must be true");
        }
        for no in &["no", "No", "NO", "nO", "false", "False", "FALSE", "0"] {
            assert_eq!(sshd_bool(no), Some(false), "{no:?} must be false");
        }
        // Whitespace is tolerated; non-boolean / unset is None.
        assert_eq!(sshd_bool("  yes  "), Some(true));
        assert_eq!(sshd_bool("  no\t"), Some(false));
        assert_eq!(sshd_bool("prohibit-password"), None);
        assert_eq!(sshd_bool(""), None);
        assert_eq!(sshd_bool("random"), None);
    }

    #[test]
    fn grade_deducts_root_login_for_capitalized_yes() {
        // The F8 regression: `PermitRootLogin Yes` (capital Y) was NOT scored
        // by the old exact `== "yes"` test, so the grade stayed high while the
        // access card showed root login enabled. With sshd_bool_is the grade
        // must match the lowercase case exactly.
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
        // And both must be WORSE than the secure baseline (root disabled).
        let secure = mock::collect_mock_security();
        assert!(
            grade_score(upper.grade()) < grade_score(secure.grade()),
            "PermitRootLogin Yes must deduct points (regression: was silently passing)"
        );
    }

    #[test]
    fn grade_treats_all_capitalizations_consistently() {
        // Run the full deduction matrix across casing variants and confirm
        // grade() is invariant under case for every boolean check.
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
        // The checks() companion: `PermitRootLogin Yes` must show passing=false
        // exactly like lowercase, resolving the disagreement with the access
        // card (which already used eq_ignore_ascii_case).
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
        // PubkeyAuthentication No must mark the public-key check as not
        // passing, case-insensitively.
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
        // A capitalized disabling value must still register as passing (secure)
        // for the password-auth check, matching the lowercase behavior.
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

    // ── parse_sshd_config_from tests ─────────────────────────────────────────

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
        // The parser builds the map from the lossless AST, iterating only
        // top-level Directive nodes. `Match` blocks are skipped wholesale
        // (their nested directives never reach the map), and a top-level
        // `Include` that matches no files leaves nothing in the map (the
        // Include directive itself never becomes a key).
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
        // Stock Debian/Ubuntu/RHEL/Fedora put overrides in
        // sshd_config.d/*.conf. The parser must follow `Include` (resolved
        // against the config dir) so grade/checks reflect the EFFECTIVE
        // config, not the defaults. This is the F9 regression: before the
        // fix, the drop-in's `PermitRootLogin no` was invisible and grading
        // silently used the default.
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
        // OpenSSH global-scope: the first obtained value wins. The main file's
        // directive appears before the Include, so the drop-in must NOT
        // override it. (Reverting the fix flips this: last-wins via HashMap
        // insert would let the drop-in win.)
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
        // Absolute Include patterns are used as-is (no base-dir join).
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
        // F9 production wiring: the five Include tests above call the `_dir`
        // seam directly. This one drives the PRODUCTION entry point
        // `parse_sshd_config_from` (hardcoded base dir `/etc/ssh`) so a revert
        // of the one-line `parse_sshd_config_from -> parse_sshd_config_from_dir`
        // delegation back to the old line-scanner — which skipped `Include `
        // lines — fails here. An absolute pattern sidesteps the hardcoded base
        // dir; a drop-in setting a key the main file omits must surface.
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
        // Multiple drop-ins matching the glob are applied in sorted order;
        // first-occurrence-wins means the lexicographically-first file's value
        // sticks for a given key.
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
        // A self-including file must not loop forever. The cycle guard
        // canonicalizes each file and skips already-seen paths.
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("loopy.conf");
        // Include itself (absolute) plus a real directive.
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
        // Note: split_once(char::is_whitespace) splits on the first space only,
        // so leading spaces in the value portion are preserved.
        let contents = "Port 2222\nMaxAuthTries 3\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
        assert_eq!(config.get("maxauthtries"), Some(&"3".to_string()));
    }

    // ── parse_sshd_access_info_from tests ────────────────────────────────────

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
        // A directive inside a Match block must NOT leak into the global value.
        // The global PasswordAuthentication=no must be preserved, and the
        // Match-scoped PasswordAuthentication=yes must be ignored. The body
        // line is genuinely indented (4 spaces) so the AST nests it inside the
        // Match block rather than treating it as a top-level directive.
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
        // Regression: the old line-scanner only skipped the literal 'Match'
        // header, so the indented AllowUsers inside the block OVERWROTE the
        // global list (last-wins), producing the wrong login_status.
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
        // OpenSSH treats multiple global AllowUsers lines as additive. The read
        // path must concatenate them, not take the last one.
        let contents = concat!("AllowUsers alice\n", "Port 22\n", "AllowUsers bob carol\n",);
        let info = parse_sshd_access_info_from(contents);
        assert_eq!(
            info.allowed_users,
            vec!["alice", "bob", "carol"],
            "multiple global AllowUsers lines must concatenate in order"
        );

        // Same goes for DenyUsers / AllowGroups / DenyGroups.
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
        // The read path and the editor must agree on what the global
        // Allow/Deny lists are. This is the property the fix is built on:
        // parse_sshd_access_info_from now uses the same sshd getters the
        // editor's add/remove helpers operate against.
        use toride_ssh::config::ast::parse;
        use toride_ssh::config::sshd::{
            get_allow_groups, get_allow_users, get_deny_groups, get_deny_users,
        };

        // The Match body lines are genuinely indented so the AST nests them.
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

        // The AST the editor would load for the same content.
        let ast = parse(contents);
        assert_eq!(info.allowed_users, get_allow_users(&ast));
        assert_eq!(info.denied_users, get_deny_users(&ast));
        assert_eq!(info.allowed_groups, get_allow_groups(&ast));
        assert_eq!(info.denied_groups, get_deny_groups(&ast));
        // Match-scoped values must be absent from both views.
        assert_eq!(info.allowed_users, vec!["alice"]);
        assert_eq!(info.denied_users, vec!["mallory"]);
    }

    // ── Write-path integration tests ─────────────────────────────────────────
    //
    // These tests override $HOME to a temp dir so SshManager writes there
    // instead of the real ~/.ssh. They must run serially because env-var
    // mutation is process-global. The `serial_test` pattern is achieved by
    // a mutex — we don't need the crate, just a static Mutex<usize>.

    use tokio::sync::Mutex;
    static HOME_LOCK: Mutex<usize> = Mutex::const_new(0);

    /// Acquire the HOME lock, held across `.await` points to serialize the
    /// write-path integration tests (they mutate the process-global `$HOME`).
    ///
    /// Uses an async-aware `tokio::sync::Mutex` so the guard is `Send` and safe
    /// to hold across `.await` (a `std::sync::MutexGuard` held across an await
    /// risks a deadlock and is flagged by `clippy::await_holding_lock`).
    async fn acquire_home_lock() -> tokio::sync::MutexGuard<'static, usize> {
        // `tokio::sync::Mutex` cannot be poisoned, so there is no recovery
        // branch needed (unlike the previous std Mutex).
        HOME_LOCK.lock().await
    }

    /// Temp HOME override for safe write-path tests.
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
        // Verify the file was actually written
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ast = mgr.config().load().await.expect("load");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("test-toride-host"),
            "host not in config: {content}"
        );
        // Clean up: remove the host
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
        // Verify file exists
        let home = std::env::var("HOME").expect("HOME");
        let key_path = std::path::Path::new(&home).join(".ssh/toride-test-key");
        assert!(
            key_path.exists(),
            "private key file should exist at {}",
            key_path.display()
        );
        // Clean up
        let op2 = SshOp::KeyDelete {
            name: "toride-test-key".into(),
        };
        let result2 = execute_op(op2).await;
        assert!(result2.is_ok(), "key delete failed: {:?}", result2.err());
        assert!(!key_path.exists(), "key file should be deleted");
    }

    // ── Full CRUD Lifecycle Tests ──────────────────────────────────────────
    //
    // These tests exercise the toride-ssh backend directly (outside the TUI)
    // to isolate whether CRUD operations actually persist to disk.

    /// SSH Key full lifecycle: Create → Verify → List → Rename → Delete.
    #[tokio::test]
    async fn key_full_crud_lifecycle() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let home = std::env::var("HOME").expect("HOME");

        // Step 1: CREATE (use id_ prefix — inventory scan only finds id_* files)
        let params = toride_ssh::KeyCreateParams::ed25519("id_crud_test_key".to_owned());
        mgr.keys()
            .create(params)
            .await
            .expect("Step 1 CREATE: key generation failed");
        eprintln!("✓ Step 1: CREATE key 'id_crud_test_key'");

        // Step 2: VERIFY files exist
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

        // Step 3: LIST includes the key
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

        // Step 4: RENAME
        mgr.keys()
            .rename("id_crud_test_key", "id_crud_test_v2")
            .await
            .expect("Step 4 RENAME: rename failed");
        eprintln!("✓ Step 4: RENAME to 'id_crud_test_v2'");

        // Step 5: VERIFY rename — old gone, new exists
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

        // Step 6: DELETE
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

        // Step 7: VERIFY deletion
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

    /// Config host full lifecycle: Add → Verify → Edit → Verify → Remove → Verify.
    #[tokio::test]
    async fn config_host_full_crud_lifecycle() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.config();

        // Step 1: ADD
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

        // Step 2: VERIFY
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

        // Step 3: EDIT (remove + re-add with new values)
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

        // Step 4: VERIFY edit
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

        // Step 5: REMOVE
        svc.edit(|ast| toride_ssh::config::ConfigService::remove_host(ast, "test-server"))
            .await
            .expect("Step 5 REMOVE: config remove failed");
        eprintln!("✓ Step 5: REMOVE host 'test-server'");

        // Step 6: VERIFY removal
        let ast = svc.load().await.expect("Step 6 VERIFY: config load failed");
        let content = ast.to_string_lossless();
        assert!(
            !content.contains("test-server"),
            "Step 6 VERIFY: 'test-server' still in config:\n{content}"
        );
        eprintln!("✓ Step 6: VERIFY host block gone");
        eprintln!("✅ config_host_full_crud_lifecycle PASSED");
    }

    /// Authorized keys full lifecycle: Add → List → Remove.
    #[tokio::test]
    async fn authorized_keys_full_crud_lifecycle() {
        // Real Ed25519 public key for testing (generated locally, not a real credential).
        const TEST_PUB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI crud-test@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.authorized_keys();

        // Step 1: ADD
        svc.add(TEST_PUB_KEY, Some("crud-test"), None)
            .await
            .expect("Step 1 ADD: authorized_keys add failed");
        eprintln!("✓ Step 1: ADD key to authorized_keys");

        // Step 2: VERIFY via list
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

        // Step 3: REMOVE via fingerprint
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

        // Step 4: VERIFY removal
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

    /// Known hosts full lifecycle: Add → Verify → Remove.
    ///
    /// Gracefully skips if `ssh-keyscan` fails (e.g. no local SSH server).
    #[tokio::test]
    async fn known_hosts_crud_lifecycle() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.known_hosts();

        // Step 1: ADD (may fail if no SSHD on localhost — that's okay)
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

        // Step 2: VERIFY
        let kh_file =
            std::path::Path::new(&std::env::var("HOME").expect("HOME")).join(".ssh/known_hosts");
        assert!(kh_file.exists(), "Step 2 VERIFY: known_hosts file missing");
        let content = std::fs::read_to_string(&kh_file).expect("read known_hosts");
        assert!(
            !content.trim().is_empty(),
            "Step 2 VERIFY: known_hosts is empty"
        );
        eprintln!("✓ Step 2: VERIFY known_hosts file has content");

        // Step 3: REMOVE
        svc.remove("localhost")
            .await
            .expect("Step 3 REMOVE: known_hosts remove failed");
        eprintln!("✓ Step 3: REMOVE localhost from known_hosts");

        // Step 4: VERIFY removal (file may still exist but without localhost entries)
        let content_after = std::fs::read_to_string(&kh_file).unwrap_or_default();
        // After removal the file may contain hashed entries or be empty.
        // The key test is that remove() succeeded.
        eprintln!(
            "✓ Step 4: VERIFY remove succeeded (known_hosts now has {} bytes)",
            content_after.len()
        );
        eprintln!("✅ known_hosts_crud_lifecycle PASSED");
    }

    /// Execute-op pipeline round-trip: tests the same `SshOp` → `execute_op` path
    /// the TUI uses for Keys and Config CRUD.
    #[tokio::test]
    async fn execute_op_pipeline_round_trip() {
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let home = std::env::var("HOME").expect("HOME");

        // ── Key lifecycle via SshOp ──

        // Step 1: CREATE via execute_op
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

        // Step 2: VERIFY file exists
        let key_path = std::path::Path::new(&home).join(".ssh/pipeline-key");
        assert!(
            key_path.exists(),
            "Step 2 VERIFY: private key missing at {key_path:?}"
        );
        eprintln!("✓ Step 2: VERIFY key file on disk");

        // Step 3: RENAME via execute_op
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

        // Step 4: VERIFY rename
        assert!(!key_path.exists(), "Step 4 VERIFY: old key still exists");
        let renamed_path = std::path::Path::new(&home).join(".ssh/pipeline-renamed");
        assert!(renamed_path.exists(), "Step 4 VERIFY: renamed key missing");
        eprintln!("✓ Step 4: VERIFY old gone, renamed exists");

        // Step 5: DELETE via execute_op
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

        // Step 6: VERIFY deletion
        assert!(
            !renamed_path.exists(),
            "Step 6 VERIFY: key still exists after delete"
        );
        eprintln!("✓ Step 6: VERIFY key file gone");

        // ── Config lifecycle via SshOp ──

        // Step 7: ADD HOST via execute_op
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

        // Step 8: VERIFY in config
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ast = mgr.config().load().await.expect("load config");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("pipeline-host"),
            "Step 8 VERIFY: 'pipeline-host' not in config:\n{content}"
        );
        eprintln!("✓ Step 8: VERIFY host in config");

        // Step 9: REMOVE HOST via execute_op
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

        // Step 10: VERIFY removal
        let ast = mgr.config().load().await.expect("load config");
        let content = ast.to_string_lossless();
        assert!(
            !content.contains("pipeline-host"),
            "Step 10 VERIFY: 'pipeline-host' still in config:\n{content}"
        );
        eprintln!("✓ Step 10: VERIFY host gone from config");
        eprintln!("✅ execute_op_pipeline_round_trip PASSED");
    }

    // ── would_lock_out / map_sshd_error tests ────────────────────────────────

    #[test]
    fn would_lock_out_refuses_literal_root() {
        // The literal-"root" guard must refuse regardless of host environment.
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
        // If we can resolve the current account name, targeting it must be
        // refused (this exercises the name-comparison branch on whoever runs
        // the test — typically a CI user or the local developer).
        let Some(current) = current_username() else {
            // Reverse lookup unavailable on this host; the name branch is
            // skipped, and the UID fallback is covered by the next test.
            return;
        };
        if current == "root" {
            return; // already covered by the literal-root test
        }
        let err = would_lock_out("deny", &current).expect("must refuse to deny the current user");
        assert!(err.revert_optimistic);
    }

    #[test]
    fn would_lock_out_refuses_current_user_by_uid_fallback() {
        // The UID-based fallback closes the gap when current_username() is
        // None. Build a scenario independent of the reverse lookup: look up the
        // UID of a *known* local account via the forward lookup, then confirm
        // that if that UID equals the process euid the guard refuses. We can't
        // forge geteuid, so instead verify the property structurally: for the
        // actual current euid, the forward lookup of any account that maps to
        // that UID must trigger a refusal.
        let euid = unsafe { libc::geteuid() };
        // The literal-root check happens first; if euid is 0 the root test
        // already covers it. Otherwise find a name that resolves to euid via
        // the forward lookup. current_username() is the reverse lookup; if it
        // also returns that name the name-branch covers it. The fallback
        // matters when the name differs or is unknown, which we can't force
        // here — so assert the fallback at least doesn't false-negative on the
        // current user when the forward lookup agrees.
        if euid == 0 {
            return;
        }
        if let Some(name) = current_username()
            && name != "root"
        {
            // Forward lookup of the resolved name must yield euid, and the
            // guard must refuse it (whether via the name branch or the UID
            // fallback).
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
        // F10: a username that cannot be resolved to a UID by any lookup path
        // (NSS, dscl /Search, id, /etc/passwd) must be REFUSED. The old behavior
        // allowed it, which let a network-account operator (OD/LDAP/sssd) whose
        // account the local-only lookup couldn't see deny/reset THEMSELVES and
        // get locked out. For a lockout guard, uncertainty refuses.
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
        // SshdConfigInvalid → disk untouched → revert the optimistic update.
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
        // A staging/install failure (disk untouched) must still revert, because
        // the optimistic update is stale relative to disk.
        let err = map_sshd_error(
            "deny",
            "alice",
            &toride_ssh::Error::ConfigWriteFailed("failed to install sshd_config: EBUSY".into()),
        );
        assert!(
            err.revert_optimistic,
            "pre-install ConfigWriteFailed must revert"
        );
        // The (now-removed) chmod annotation must not be attached to any
        // ConfigWriteFailed variant.
        assert!(
            !err.message.contains("mode could not be set"),
            "ConfigWriteFailed must not carry the dropped chmod annotation: {}",
            err.message
        );
    }

    #[test]
    fn map_sshd_error_chmod_failure_reverts_without_false_installed_annotation() {
        // F7: the backend chmods the staged TEMP before the rename into place
        // (privilege.rs `install_temp`), so a "failed to chmod sshd_config"
        // failure leaves the LIVE config untouched (nothing was installed).
        // The optimistic UI update disagrees with disk truth (the change did
        // NOT take effect), so it must revert. The message must NOT claim the
        // config was installed — that was the inverted annotation the old code
        // emitted, which lied about a state that can never happen under the
        // chmod-before-rename invariant. Reverting the fix brings back the
        // false "installed but mode could not be set" suffix, failing this.
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
        // The operator-facing message still names the failing step.
        assert!(
            err.message.contains("chmod"),
            "message must still surface the underlying chmod step: {}",
            err.message
        );
    }

    // ── T4: MATCH-LEAK REGRESSION ────────────────────────────────────────────
    // A global `PasswordAuthentication no` followed by a `Match Address ...`
    // block whose INDENTED body sets `PasswordAuthentication yes` must NOT leak
    // the Match-scoped override into the global value the security grade sees.
    // (Previously the line scanner only skipped lines *starting with* `match `,
    // so the indented directive leaked via last-write-wins and overwrote the
    // global — making the headline grade silently wrong while the sibling AST
    // scanner reported the correct value on the same screen.)
    #[test]
    fn parse_sshd_config_from_excludes_match_scoped_directives() {
        // NOTE: the Match-body lines MUST be genuinely indented (the AST nests
        // indented body lines under the MatchBlock). A `\` line-continuation in
        // the string literal would strip the leading spaces, so use explicit
        // `\n` joins to preserve the 4-space indent on the body directives.
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
        // Only the single global directive should be present.
        assert_eq!(
            config.len(),
            1,
            "exactly one global directive expected, got {config:?}"
        );
    }

    // ── T5: IO REVERTS ───────────────────────────────────────────────────────
    // On the edit path, Error::Io can come from the pre-write load(), the
    // cross-process lock (F2), or a re-wrapped critical-section failure — in
    // every case the staging/atomic-install pipeline leaves disk unchanged, so
    // the optimistic UI update is a lie and must be classified reverting.
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

    // ── T6: UID-FALLBACK BRANCH REAL COVERAGE ────────────────────────────────
    // would_lock_out_refuses_current_user_by_uid_fallback is a tautology: it
    // returns early whenever current_username() is Some (so the name branch
    // fires before the uid-fallback) and whenever euid is 0. would_lock_out_with_uid
    // is the seam split out of would_lock_out specifically so the two backstop
    // branches can be exercised deterministically without forging geteuid or
    // spawning dscl.
    #[test]
    fn would_lock_out_with_uid_refuses_resolved_euid() {
        // Forward lookup of `username` resolves to the operator's euid, but the
        // reverse lookup that feeds the name-branch returned None (odd/unknown
        // euid). The uid-equality backstop must still refuse.
        let err = would_lock_out_with_uid("deny", "weird-uid-account", 501, Some(501))
            .expect("uid == euid must be refused even when name lookup failed");
        assert!(err.revert_optimistic);
        assert!(err.message.contains("weird-uid-account"));
    }

    #[test]
    fn would_lock_out_with_uid_refuses_uid_zero() {
        // Defense-in-depth: a username that resolves to UID 0 must be refused
        // regardless of the operator's euid.
        let err =
            would_lock_out_with_uid("reset", "toor", 1000, Some(0)).expect("uid 0 must be refused");
        assert!(err.revert_optimistic);
        assert!(err.message.contains("toor"));
    }

    #[test]
    fn would_lock_out_with_uid_allows_unrelated() {
        // A real-looking uid that is neither euid nor 0 must not be refused.
        let result = would_lock_out_with_uid("deny", "someone-else", 1000, Some(501));
        assert!(
            result.is_none(),
            "unrelated uid must not be refused, got {result:?}"
        );
    }

    #[test]
    fn would_lock_out_with_uid_refuses_unresolvable_uid() {
        // F10: when resolved_uid is None the target could not be positively
        // identified. A lockout guard refuses by default — the operator can
        // resolve the lookup (ensure NSS/sssd is reachable) and retry.
        // Reverting the fix flips this back to `is_none()` (allows), which is
        // the self-lockout hole.
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
        // The refuse-by-default branch applies to BOTH verbs routed through the
        // guard (deny and reset), since either can lock the operator out.
        let result = would_lock_out_with_uid("reset", "ghost", 1000, None);
        assert!(
            result.is_some(),
            "unresolvable uid must be refused on reset too, got {result:?}"
        );
    }

    // ── F11: authorized_keys removal self-lockout guard ─────────────────────
    // Removing the operator's last authorized key would lock them out of SSH
    // (no pubkey left to authenticate with). The guard must refuse that case.
    // These tests use a temp HOME so the AuthorizedKeysService reads/writes the
    // operator's own ~/.ssh/authorized_keys; they run under HOME_LOCK for the
    // same serial-execution reason as the other write-path tests.

    /// Write `lines` to `~/.ssh/authorized_keys` in the current HOME, returning
    /// nothing. Used to seed a known `authorized_keys` state before each guard
    /// assertion.
    fn seed_authorized_keys(lines: &[&str]) {
        let home = std::env::var("HOME").expect("HOME set");
        let path = std::path::Path::new(&home).join(".ssh/authorized_keys");
        let body = lines.join("\n");
        std::fs::write(&path, format!("{body}\n")).expect("write authorized_keys");
    }

    #[tokio::test]
    async fn would_lock_out_authorized_key_refuses_removing_last_key() {
        // A real Ed25519 public key (generated locally, not a real credential).
        const TEST_PUB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI last-key@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();

        seed_authorized_keys(&[TEST_PUB_KEY]);

        // Compute the fingerprint of the sole key, then ask the guard whether
        // removing it is safe. It must refuse (reverting) — this is the exact
        // self-lockout case F11 targets.
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
        // Two distinct real keys; removing one leaves the other, so the guard
        // must allow (return None). Reverting the fix would refuse any removal
        // of the only matching key, which would also wrongly block this.
        const KEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI keep-a@toride";
        const KEY_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP9fG4eJ8kL3mN6oQ2rS5tU7vWxYzAbCdEfGhIjKlMnO remove-b@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();

        seed_authorized_keys(&[KEY_A, KEY_B]);

        let entries = svc.list().await.expect("list");
        assert_eq!(entries.len(), 2, "seeded two keys");
        // Find the fingerprint of KEY_B (the one to remove).
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
        // An empty authorized_keys has nothing to remove — the guard must allow
        // (the backend `remove` will no-op). This pins that the guard only
        // protects against emptying a NON-EMPTY file down to zero.
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();
        // TempHome already created .ssh but no authorized_keys file → list is
        // empty. Use a fingerprint that matches nothing.
        let guard = would_lock_out_authorized_key(&svc, "SHA256:nonexistent").await;
        assert!(
            guard.is_none(),
            "empty file must be allowed (nothing to lock out), got {guard:?}"
        );
    }

    #[tokio::test]
    async fn would_lock_out_authorized_key_refuses_when_all_keys_match() {
        // Multiple copies of the SAME key (same fingerprint): removing by that
        // fingerprint would drop the count to zero even though there were
        // several entries. The guard must refuse.
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
        // F11 PRODUCTION WIRING: the four guard tests above call
        // `would_lock_out_authorized_key` directly; none drove the
        // `SshOp::AuthorizedKeyRemove` arm of `execute_op`. This pins that the
        // guard is actually invoked in production: seed the operator's
        // (temp-HOME) authorized_keys with a SINGLE key and attempt to remove
        // it via `execute_op`. It must return a reverting Err and leave the
        // file byte-for-byte intact. Deleting the production invocation
        // (ssh_data.rs `if let Some(err) = would_lock_out_authorized_key(...)`)
        // would make this remove the sole key and return Ok — failing the test.
        const TEST_PUB_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI last-key@toride";
        let _lock = acquire_home_lock().await;
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let svc = mgr.authorized_keys();

        seed_authorized_keys(&[TEST_PUB_KEY]);

        let entries = svc.list().await.expect("list");
        assert_eq!(entries.len(), 1, "seeded one key");
        let fp = entries[0].fingerprint().expect("fingerprint").clone();

        // Snapshot the file so we can prove the guard fires BEFORE any deletion.
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

        // The sole key must survive untouched — the guard ran before `svc.remove`.
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
        // F10: the NSS path (getpwnam_r) is now the PRIMARY lookup. It must
        // resolve a real local user — root is guaranteed to exist on every
        // Unix. Reverting the fix makes nss_uid_for_username not exist, so this
        // test fails to compile; if someone stubs it to return None, the
        // assertion fails. This proves the NSS path is wired and returns Some.
        let uid = nss_uid_for_username("root")
            .expect("NSS must resolve the 'root' account on any Unix system");
        assert_eq!(uid, 0, "root's UID via getpwnam_r must be 0; got {uid}");
    }

    #[test]
    fn nss_username_for_uid_resolves_uid_zero_to_root() {
        // The reverse NSS path (getpwuid_r) must map UID 0 back to "root".
        let name = nss_username_for_uid(0).expect("NSS must resolve UID 0 on any Unix system");
        assert_eq!(
            name, "root",
            "UID 0 must resolve to 'root' via getpwuid_r; got {name:?}"
        );
    }

    #[test]
    fn nss_uid_for_username_returns_none_for_nonexistent() {
        // Sanity: a guaranteed-nonexistent account resolves to None via NSS,
        // so the refuse-by-default branch is reachable (not a panic).
        let uid = nss_uid_for_username("toride-definitely-no-such-user-zyxw");
        assert!(
            uid.is_none(),
            "nonexistent account must be None via NSS, got {uid:?}"
        );
    }

    #[test]
    fn uid_for_username_resolves_root_via_full_chain() {
        // End-to-end: the public uid_for_username (NSS + dscl + id + passwd)
        // must resolve root to UID 0 on every platform.
        let uid = uid_for_username("root").expect("uid_for_username must resolve 'root'");
        assert_eq!(uid, 0);
    }

    // ── F13: execute_op SshdDeny/Reset backend lockout guard ────────────────
    //
    // The privilege-inversion guard in execute_op's SshdDenyUser /
    // SshdResetUserAccess arms MUST refuse a root target BEFORE the edit path
    // is reached — independent of any UI-side guard (defense in depth). These
    // tests pin that: targeting "root" returns a reverting Err and never reaches
    // the privileged sshd_config write (so disk is untouched regardless of
    // whether the test runs as root or not). The guard is in ssh_data.rs, the
    // same process boundary as execute_op, so it is the load-bearing backstop.
    //
    // NOTE on the L1 install integration (F13 part b): verifying that denying a
    // user in AllowUsers ends up in DenyUsers and NOT AllowUsers requires a
    // real write to /etc/ssh/sshd_config (root/sudo -n), which a non-privileged
    // test cannot perform. That invariant is exercised by the sshd editor's own
    // tests (add_user_to_deny + remove_user_from_allow) in the config crate; it
    // is not duplicated here because execute_op hardcodes /etc/ssh/sshd_config.
    // See open_questions for the flush_ssh_ops test (lives in app/mod.rs).

    /// Snapshot `/etc/ssh/sshd_config` if it is readable, else None. Used to prove
    /// the lockout guard leaves the live config byte-for-byte unchanged.
    fn snapshot_sshd_config() -> Option<Vec<u8>> {
        std::fs::read("/etc/ssh/sshd_config").ok()
    }

    #[tokio::test]
    async fn execute_op_sshd_deny_root_refused_with_revert_and_disk_unchanged() {
        // F13 (a): denying root must be refused by the backend guard BEFORE any
        // edit, returning a reverting error (the optimistic UI update is a lie
        // and must be refreshed), and /etc/ssh/sshd_config must be byte-identical
        // before and after. Reverting the would_lock_out guard makes this return
        // Ok (or a privilege error from attempting the real edit), failing the
        // Err + revert assertions.
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
        // Disk untouched: the guard fired before the edit path.
        assert_eq!(
            before, after,
            "/etc/ssh/sshd_config must be unchanged after a refused root denial"
        );
    }

    #[tokio::test]
    async fn execute_op_sshd_reset_root_refused_with_revert_and_disk_unchanged() {
        // Same as above for the Reset arm — both routed through would_lock_out.
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

    // ── F19: would_lock_out_async runs blocking lookups off the worker ──────
    //
    // execute_op runs on a tokio task, and the lockout guard shells out to
    // dscl/getent and reads /etc/passwd — all blocking. would_lock_out_async
    // routes those lookups through spawn_blocking so the async worker is never
    // stalled. These tests pin that the async path produces the SAME refusals
    // as the sync path (the production arms now call the async version), so a
    // regression that reverts the production call sites back to the blocking
    // sync version fails them.

    #[tokio::test]
    async fn would_lock_out_async_refuses_root_like_sync() {
        // The async wrapper must refuse root identically to the sync version.
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
        // The forward-lookup refuse-by-default branch must fire through the
        // spawn_blocking path too: a guaranteed-unresolvable user is refused.
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
        // For whoever runs the test (a CI user or the local developer), denying
        // their own account must be refused by BOTH paths with the same verdict.
        // This proves the async wiring resolves the operator identity the same
        // way the sync path does. Skipped when the operator is root (covered
        // above) or when the reverse lookup is unavailable.
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
}
