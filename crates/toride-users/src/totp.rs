//! TOTP/2FA enrollment via `google-authenticator`.
//!
//! Provides functions to set up and manage TOTP-based two-factor
//! authentication using the `google-authenticator` PAM module.

#[cfg(feature = "client")]
use std::fmt;

use crate::{Error, Result, paths::UserPaths};

/// A redacting wrapper around the sensitive output of `google-authenticator`
/// (the TOTP seed plus the one-time scratch codes).
///
/// The captured stdout is highly sensitive: anyone who reads it can generate
/// valid 2FA codes for the account. [`TotpSecret`] makes accidental disclosure
/// through logging hard:
///
/// - [`Debug`](fmt::Debug) renders as `TotpSecret { **REDACTED** }`, so a stray
///   `{:?}` (or a struct deriving `Debug` over a field of this type, or a
///   `tracing` macro that captures the value by debug) never prints the seed.
/// - The buffer is [`zeroize`](::zeroize)d on drop, so the secret is not left
///   in freed heap memory longer than necessary.
/// - [`Display`](fmt::Display) intentionally renders the underlying value, and
///   [`expose_secret`](Self::expose_secret) hands out a `&str`, because the
///   *whole purpose* of enrollment is to surface the seed/scratch codes to the
///   operator exactly once (so they can enroll an authenticator app and store
///   the scratch codes). Use these only on a deliberate, user-facing sink --
///   never in a log line.
///
/// Construct it via [`TotpSecret::new`], which takes ownership of the input
/// bytes so the caller's copy is dropped.
#[cfg(feature = "client")]
pub struct TotpSecret {
    inner: String,
}

#[cfg(feature = "client")]
impl TotpSecret {
    /// Wrap a captured enrollment output, taking ownership so the caller's
    /// copy goes out of scope.
    ///
    /// The argument is moved (not copied); the caller should drop any other
    /// reference to the same bytes.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Deliberately expose the underlying secret as a `&str`.
    ///
    /// Reserve this for a user-facing sink (e.g. writing the seed to stdout so
    /// the operator can enroll an authenticator app). Never feed the result
    /// into a `tracing`/`log` call or store it in a long-lived structure.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }

    /// Consume the wrapper and return the raw secret `String`.
    ///
    /// Use when ownership of the bytes is required (e.g. handing the value to
    /// an API that takes `String`). The returned `String` is **not** zeroized
    /// on drop, so prefer [`expose_secret`](Self::expose_secret) where a
    /// borrow suffices.
    #[must_use]
    pub fn into_inner(mut self) -> String {
        // The wrapper implements `Drop` (to zeroize), so we cannot move the
        // field out directly. Swap the secret out for an empty `String` (which
        // the subsequent `Drop` zeroizes as a harmless no-op) and return the
        // original bytes -- no `unsafe` required (this crate is
        // `#![deny(unsafe_code)]`).
        std::mem::take(&mut self.inner)
    }
}

#[cfg(feature = "client")]
impl fmt::Display for TotpSecret {
    /// Renders the underlying secret. This is deliberate: the caller is
    /// surfacing the seed/scratch codes to the operator on a user-facing sink.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

#[cfg(feature = "client")]
impl fmt::Debug for TotpSecret {
    /// Always redacts. Prevents accidental leakage via `{:?}`, derived
    /// `Debug` on containing structs, and `tracing` debug captures.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpSecret")
            .field("inner", &"**REDACTED**")
            .finish()
    }
}

#[cfg(feature = "client")]
impl zeroize::ZeroizeOnDrop for TotpSecret {}

#[cfg(feature = "client")]
impl Drop for TotpSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.inner.zeroize();
    }
}

#[cfg(feature = "client")]
impl AsRef<str> for TotpSecret {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

#[cfg(feature = "client")]
impl std::ops::Deref for TotpSecret {
    type Target = str;

    /// Allows `&secret` call sites (`.chars()`, slicing, etc.) without
    /// spelling out `expose_secret()`. Does not redact -- this is a deliberate
    /// read by the holding code.
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Check if TOTP is set up for a user.
///
/// Checks for the existence of `~<username>/.google_authenticator`. The home
/// directory is resolved by reading `paths.passwd` so a custom base dir (e.g.
/// for tests or chrooted operation) is honored.
pub fn is_totp_configured(paths: &UserPaths, username: &str) -> Result<bool> {
    let home = get_user_home(paths, username)?;
    let ga_file = home.join(".google_authenticator");
    Ok(ga_file.exists())
}

/// Get the path to a user's `.google_authenticator` file.
///
/// # Errors
///
/// Returns [`Error::UserNotFound`] if the user's home directory cannot be
/// determined.
pub fn totp_file_path(paths: &UserPaths, username: &str) -> Result<std::path::PathBuf> {
    let home = get_user_home(paths, username)?;
    Ok(home.join(".google_authenticator"))
}

/// Build the `google-authenticator` argument vector used for enrollment.
///
/// Returns the exact argv (without the binary name) so the privilege/argv
/// contract is unit-testable without spawning a process. The flags select:
///
/// - Time-based (TOTP)
/// - Rate-limiting enabled (3 attempts per 30 seconds)
/// - Window size of 3 (allows slight clock drift)
/// - Emergency scratch codes generated
/// - Force (non-interactive)
#[cfg(feature = "client")]
fn enrollment_argv() -> Vec<&'static str> {
    vec![
        "-t",      // time-based
        "-d",      // disallow reuse
        "-r", "3", // rate limit: 3 per 30s
        "-w", "3", // window size
        "-s",      // generate scratch codes
        "-f",      // force (non-interactive)
    ]
}

/// Build the full argv for running `google-authenticator` as the TARGET user
/// via `runuser`, so the resulting `~user/.google_authenticator` file is owned
/// by that user (not root). PAM (`pam_google_authenticator.so`) runs as the
/// logging-in user and must be able to read this file; a root-owned 0600 file
/// is unreadable and silently defeats 2FA.
///
/// The argv is returned as owned strings so it can be fed directly to `duct`
/// and asserted on in tests. The leading element is the `runuser` invocation;
/// the binary name is returned separately by the caller.
#[cfg(feature = "client")]
fn enrollment_argv_as_user(username: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "-u".to_owned(),
        username.to_owned(),
        "--".to_owned(),
    ];
    argv.extend(enrollment_argv().into_iter().map(String::from));
    argv
}

/// Enforce the security-sensitive post-conditions on the TOTP state file:
/// owner = `uid:gid` and mode 0600.
///
/// `google-authenticator` creates the file 0600, but when invoked via
/// `runuser` the owner is already correct. We still explicitly set the mode
/// (in case a system umask or a future flag changes the default) and chown to
/// the resolved target uid:gid (idempotent when already correct). Resolving
/// the uid/gid from `paths.passwd` keeps this testable against a chroot.
#[cfg(feature = "client")]
fn enforce_totp_file_owner_mode(
    paths: &UserPaths,
    username: &str,
    file: &std::path::Path,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // mode 0600, always.
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(file, perms)?;

    // Resolve the target uid:gid from passwd so a custom base dir is honored.
    let entries = crate::parse::read_passwd(&paths.passwd)?;
    let entry = entries
        .iter()
        .find(|e| e.username == username)
        .ok_or_else(|| Error::UserNotFound(username.to_owned()))?;

    let uid = entry.uid;
    let gid = entry.gid;
    // chown via the `chown` binary (keeps the crate `#![deny(unsafe_code)]`:
    // we avoid the raw `chown(2)` nix/std call that needs unsafe on some
    // targets by shelling out, mirroring the rest of this module's style).
    let chown_bin = which::which("chown").map_err(|_| Error::BinaryNotFound("chown".into()))?;
    let owner = format!("{uid}:{gid}");
    let file_str = file.to_string_lossy().into_owned();
    duct::cmd(&chown_bin, [owner.as_str(), file_str.as_str()])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "chown".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;
    Ok(())
}

/// Enroll a user in TOTP/2FA.
///
/// This function creates the initial `.google_authenticator` file by running
/// `google-authenticator` in non-interactive mode with sensible defaults:
///
/// - Time-based (TOTP)
/// - Rate-limiting enabled (3 attempts per 30 seconds)
/// - Window size of 3 (allows slight clock drift)
/// - Emergency scratch codes generated
///
/// # Security
///
/// Enrollment runs as the TARGET user via `runuser -u <user> --`, so the
/// generated `~user/.google_authenticator` is owned by that user rather than
/// root. `pam_google_authenticator.so` executes as the logging-in user and
/// must read this file; a root-owned 0600 file (the previous behavior when
/// running this as root) was unreadable by PAM and, combined with `nullok`,
/// silently bypassed 2FA. After creation we explicitly enforce mode 0600 and
/// owner = target `uid:gid`.
///
/// The generated secret key and scratch codes are sensitive, so the captured
/// `google-authenticator` stdout is returned wrapped in a [`TotpSecret`] whose
/// [`Debug`](std::fmt::Debug) impl redacts and whose buffer is zeroized on
/// drop. Callers surface it to the operator exactly once via
/// [`Display`](std::fmt::Display) or [`TotpSecret::expose_secret`]; it is never
/// logged raw by this function.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `google-authenticator` is not installed.
/// - [`Error::TotpError`] if TOTP is already configured for this user.
/// - [`Error::CommandFailed`] if the command fails.
#[cfg(feature = "client")]
pub fn enroll_totp(paths: &UserPaths, username: &str) -> Result<TotpSecret> {
    // Check if already enrolled
    if is_totp_configured(paths, username)? {
        return Err(Error::TotpError(format!(
            "TOTP already configured for user {username}"
        )));
    }

    let runuser_bin = which::which("runuser")
        .map_err(|_| Error::BinaryNotFound("runuser".into()))?;
    let user_argv = enrollment_argv_as_user(username);

    let output = duct::cmd(&runuser_bin, &user_argv)
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "runuser".to_owned(),
            code: None,
            // The duct error itself does not carry the secret (it is a spawn /
            // wait error); only the *successful* stdout is sensitive, and that
            // is wrapped below.
            stderr: e.to_string(),
        })?;

    // Enforce owner/mode regardless of how the file was created: the PAM
    // module runs as <user> and a root-owned 0600 file is unreadable.
    if let Ok(ga_file) = totp_file_path(paths, username)
        && ga_file.exists()
    {
        // Best-effort hardening: do not abort enrollment on a chown
        // failure (the secret is already generated), but log it loudly so
        // an operator notices the file may be unreadable by PAM.
        if let Err(e) = enforce_totp_file_owner_mode(paths, username, &ga_file) {
            tracing::warn!(
                "TOTP enrolled for {username} but could not enforce owner/mode on {}: {e}",
                ga_file.display()
            );
        }
    }

    tracing::info!("enrolled TOTP for user {username}");
    // Wrap the sensitive stdout so it cannot be logged raw via Debug and is
    // scrubbed from memory when the caller is done with it.
    Ok(TotpSecret::new(output))
}

/// Remove TOTP configuration for a user.
///
/// Deletes the `.google_authenticator` file from the user's home directory.
/// A backup is created before deletion. The home directory is resolved by
/// reading `paths.passwd`.
///
/// # Errors
///
/// - [`Error::TotpError`] if TOTP is not configured for this user.
/// - [`Error::Io`] if the file cannot be removed.
pub fn remove_totp(paths: &UserPaths, username: &str) -> Result<()> {
    let path = totp_file_path(paths, username)?;

    if !path.exists() {
        return Err(Error::TotpError(format!(
            "TOTP not configured for user {username}"
        )));
    }

    // Backup before removal
    crate::backup::backup_file(&path, None)?;

    std::fs::remove_file(&path)?;

    tracing::info!("removed TOTP for user {username}");
    Ok(())
}

/// Enable TOTP/2FA for SSH login for a specific user.
///
/// This combines:
/// 1. TOTP enrollment via [`enroll_totp`]
/// 2. PAM configuration update for the `sshd` service
///
/// The returned [`TotpSecret`] wraps the sensitive `google-authenticator`
/// output; see [`enroll_totp`] for the redaction/zeroize contract.
///
/// # Errors
///
/// Returns any error from enrollment or PAM configuration.
#[cfg(feature = "client")]
pub fn enable_totp_ssh(paths: &UserPaths, username: &str) -> Result<TotpSecret> {
    let output = enroll_totp(paths, username)?;
    crate::pam::enable_totp_for_service(paths, "sshd")?;
    tracing::info!("enabled TOTP for SSH login for user {username}");
    Ok(output)
}

/// Disable TOTP/2FA for SSH login for a specific user.
///
/// # Errors
///
/// Returns any error from removal or PAM configuration.
pub fn disable_totp_ssh(paths: &UserPaths, username: &str) -> Result<()> {
    remove_totp(paths, username)?;
    crate::pam::disable_totp_for_service(paths, "sshd")?;
    tracing::info!("disabled TOTP for SSH login for user {username}");
    Ok(())
}

/// Resolve the home directory for a user from `paths.passwd`.
fn get_user_home(paths: &UserPaths, username: &str) -> Result<std::path::PathBuf> {
    let entries = crate::parse::read_passwd(&paths.passwd)?;
    entries
        .iter()
        .find(|e| e.username == username)
        .map(|e| std::path::PathBuf::from(&e.home))
        .ok_or_else(|| Error::UserNotFound(username.to_owned()))
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;

    #[test]
    fn enrollment_argv_uses_runuser_with_target_user() {
        // The security fix: enrollment must run as the TARGET user (via
        // `runuser -u <user> --`) so the generated file is owned by that
        // user, not root. Assert the argv shape.
        let argv = enrollment_argv_as_user("alice");
        assert_eq!(argv[0], "-u", "runuser first arg is the -u flag");
        assert_eq!(
            argv[1], "alice",
            "runuser second arg is the target username"
        );
        assert_eq!(argv[2], "--", "runuser separates flags from command");
        // The google-authenticator flags follow, unchanged from the old
        // direct-invocation argv.
        assert!(argv.contains(&"-t".to_owned()), "time-based flag present");
        assert!(argv.contains(&"-f".to_owned()), "force/non-interactive flag");
        assert!(argv.contains(&"-d".to_owned()), "disallow-reuse flag");
        // The ga flags must NOT contain the username again (it's the runuser
        // target, not a ga argument).
        assert_eq!(
            argv.iter().filter(|a| **a == "alice").count(),
            1,
            "username appears exactly once (as runuser target)"
        );
    }

    #[test]
    fn enrollment_argv_omits_nullok_and_secret_flags() {
        // Enrollment never passes anything that would weaken the file
        // permissions or skip verification.
        let argv = enrollment_argv_as_user("svc");
        assert!(!argv.iter().any(|a| a == "--secret"), "no secret flag");
    }

    #[test]
    fn enrollment_argv_is_distinct_per_user() {
        let a = enrollment_argv_as_user("alice");
        let b = enrollment_argv_as_user("bob");
        assert_ne!(a, b, "argv must differ by target user");
    }

    #[test]
    fn totp_file_path_resolves_under_home() {
        // Hermetic: build a passwd with a known home and resolve the path.
        // The home field is taken verbatim from passwd (absolute here).
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "alice:x:1000:1000::/home/alice:/bin/bash\n",
        )
        .unwrap();
        let paths = UserPaths::with_base(dir.path());
        let file = totp_file_path(&paths, "alice").unwrap();
        assert_eq!(
            file,
            std::path::PathBuf::from("/home/alice/.google_authenticator")
        );
    }

    #[test]
    fn totp_file_path_user_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(&passwd, "alice:x:1000:1000::/home/alice:/bin/bash\n").unwrap();
        let paths = UserPaths::with_base(dir.path());
        assert!(matches!(
            totp_file_path(&paths, "ghost"),
            Err(Error::UserNotFound(_))
        ));
    }

    #[test]
    fn enforce_owner_mode_resolves_uid_gid_from_passwd() {
        // We can't run chown without root, but we CAN verify the function
        // resolves the target uid:gid from passwd (it returns UserNotFound
        // before ever calling chown for a missing user). Build a passwd with a
        // known entry and a dummy file; expect an error that is NOT
        // UserNotFound (it will be a chown/permission error, proving the uid
        // was resolved).
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "alice:x:1000:1000::/home/alice:/bin/bash\n",
        )
        .unwrap();
        let paths = UserPaths::with_base(dir.path());
        let file = dir.path().join("ga");
        std::fs::write(&file, "secret\n").unwrap();

        let res = enforce_totp_file_owner_mode(&paths, "alice", &file);
        // On a non-root test runner, chown to 1000:1000 of a file we own
        // succeeds (no-op) -> Ok. On a locked-down runner it may fail with a
        // CommandFailed/permission error. Either way it must NOT be
        // UserNotFound, which would mean the uid was not resolved.
        assert!(
            !matches!(res, Err(Error::UserNotFound(_))),
            "uid/gid must be resolved from passwd before chown"
        );
    }

    #[test]
    fn enforce_owner_mode_missing_user_is_user_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(&passwd, "alice:x:1000:1000::/home/alice:/bin/bash\n").unwrap();
        let paths = UserPaths::with_base(dir.path());
        let file = dir.path().join("ga");
        std::fs::write(&file, "secret\n").unwrap();
        // mode is still set first (succeeds), then UserNotFound on chown step.
        assert!(matches!(
            enforce_totp_file_owner_mode(&paths, "ghost", &file),
            Err(Error::UserNotFound(_))
        ));
    }

    #[test]
    fn totp_secret_debug_redacts() {
        // Debug must never reveal the seed/scratch codes -- this is the format
        // tracing/derived-Debug/accidental {:?} would use.
        let secret = TotpSecret::new("JBSWY3DPEHPK3PXP 12345678".to_owned());
        let debugged = format!("{secret:?}");
        assert!(
            !debugged.contains("JBSWY3DPEHPK3PXP"),
            "Debug leaked the TOTP seed: {debugged}"
        );
        assert!(
            !debugged.contains("12345678"),
            "Debug leaked a scratch code: {debugged}"
        );
        assert!(
            debugged.contains("REDACTED"),
            "Debug should advertise it is redacted: {debugged}"
        );
    }

    #[test]
    fn totp_secret_display_surfaces_value_for_deliberate_sink() {
        // The caller's whole purpose is to show the seed/scratch codes to the
        // operator exactly once. Display (used by writeln! to the user-facing
        // sink) must therefore render the real value.
        let secret = TotpSecret::new("JBSWY3DPEHPK3PXP 12345678".to_owned());
        let displayed = format!("{secret}");
        assert_eq!(displayed, "JBSWY3DPEHPK3PXP 12345678");
    }

    #[test]
    fn totp_secret_expose_secret_and_deref_match_inner() {
        let secret = TotpSecret::new("seed 11111111 22222222".to_owned());
        assert_eq!(secret.expose_secret(), "seed 11111111 22222222");
        assert_eq!(&*secret, "seed 11111111 22222222");
        assert_eq!(secret.as_ref(), "seed 11111111 22222222");
    }

    #[test]
    fn totp_secret_into_inner_returns_value() {
        let secret = TotpSecret::new("seed 99999999".to_owned());
        let raw = secret.into_inner();
        assert_eq!(raw, "seed 99999999");
    }

    #[test]
    fn totp_secret_in_derived_debug_struct_does_not_leak() {
        // A common leak path is a struct deriving Debug with a TotpSecret
        // field. Because TotpSecret's own Debug redacts, the containing
        // struct's Debug must not leak either.
        #[derive(Debug)]
        #[expect(dead_code, reason = "fields are read only via the derived Debug")]
        struct Envelope {
            user: &'static str,
            secret: TotpSecret,
        }
        let env = Envelope {
            user: "alice",
            secret: TotpSecret::new("TOPSECRETSEED 00000000".to_owned()),
        };
        let rendered = format!("{env:?}");
        assert!(
            !rendered.contains("TOPSECRETSEED") && !rendered.contains("00000000"),
            "derived Debug leaked the secret through a containing struct: {rendered}"
        );
        assert!(rendered.contains("REDACTED"));
    }
}
