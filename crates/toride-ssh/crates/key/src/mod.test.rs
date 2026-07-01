use super::*;

#[test]
fn validate_key_name_empty() {
    assert!(validate_key_name("").is_err());
}

#[test]
fn validate_key_name_slash() {
    assert!(validate_key_name("../etc/passwd").is_err());
}

#[test]
fn validate_key_name_backslash() {
    assert!(validate_key_name("..\\etc\\passwd").is_err());
}

#[test]
fn validate_key_name_dot_dot() {
    assert!(validate_key_name("../../etc/passwd").is_err());
}

#[test]
fn validate_key_name_dot_dot_in_middle() {
    assert!(validate_key_name("foo/../bar").is_err());
}

#[test]
fn validate_key_name_valid() {
    assert!(validate_key_name("id_ed25519").is_ok());
    assert!(validate_key_name("my-key").is_ok());
    assert!(validate_key_name("key_with_underscores").is_ok());
}

#[test]
fn validate_key_name_dot_file() {
    // Dot files like ".ssh" should be valid (no path traversal)
    assert!(validate_key_name(".hidden").is_ok());
}

#[test]
fn validate_key_name_unicode() {
    // Unicode names should be valid as long as no path traversal
    assert!(validate_key_name("clé").is_ok());
}

#[test]
fn validate_key_name_just_dot_dot() {
    assert!(validate_key_name("..").is_err());
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn validate_key_name_with_spaces() {
    // Spaces in key name are unusual but not a security issue
    assert!(validate_key_name("my key").is_ok());
}

#[test]
fn validate_key_name_with_tabs() {
    assert!(validate_key_name("my\tkey").is_ok());
}

#[test]
fn validate_key_name_with_null_byte() {
    // Null bytes are now rejected to prevent path truncation attacks
    assert!(validate_key_name("my\0key").is_err());
}

#[test]
fn validate_key_name_with_control_chars() {
    assert!(validate_key_name("my\x01key").is_ok()); // Not explicitly blocked
}

#[test]
fn validate_key_name_very_long() {
    // Names up to 255 bytes are OK (filesystem limit).
    let name_255 = "a".repeat(255);
    assert!(validate_key_name(&name_255).is_ok());

    // Names over 255 bytes are rejected.
    let name_256 = "a".repeat(256);
    assert!(validate_key_name(&name_256).is_err());
}

#[test]
fn validate_key_name_exactly_255_bytes_accepted() {
    // The maximum valid key name length: exactly 255 bytes.
    let name = "k".repeat(255);
    assert_eq!(name.len(), 255);
    let result = validate_key_name(&name);
    assert!(
        result.is_ok(),
        "255-byte name should be accepted: {result:?}"
    );
}

#[test]
fn validate_key_name_exactly_256_bytes_rejected() {
    // One byte over the limit: must be rejected.
    let name = "k".repeat(256);
    assert_eq!(name.len(), 256);
    let result = validate_key_name(&name);
    assert!(result.is_err(), "256-byte name should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("255"),
        "error should mention the 255-byte limit: {err_msg}",
    );
}

#[test]
fn validate_key_name_with_equals() {
    assert!(validate_key_name("my=key").is_ok());
}

#[test]
fn validate_key_name_with_colon() {
    assert!(validate_key_name("my:key").is_ok());
}

#[test]
fn validate_key_name_with_semicolon() {
    assert!(validate_key_name("my;key").is_ok());
}

#[test]
fn validate_key_name_with_pipe() {
    assert!(validate_key_name("my|key").is_ok());
}

#[test]
fn validate_key_name_with_ampersand() {
    assert!(validate_key_name("my&key").is_ok());
}

#[test]
fn validate_key_name_with_dollar() {
    assert!(validate_key_name("my$key").is_ok());
}

#[test]
fn validate_key_name_with_backtick() {
    assert!(validate_key_name("my`key").is_ok());
}

#[test]
fn validate_key_name_with_single_quote() {
    assert!(validate_key_name("my'key").is_ok());
}

#[test]
fn validate_key_name_with_double_quote() {
    assert!(validate_key_name("my\"key").is_ok());
}

#[test]
fn validate_key_name_with_angle_brackets() {
    assert!(validate_key_name("my<key>").is_ok());
}

#[test]
fn validate_key_name_with_square_brackets() {
    assert!(validate_key_name("my[key]").is_ok());
}

#[test]
fn validate_key_name_with_curly_braces() {
    assert!(validate_key_name("my{key}").is_ok());
}

#[test]
fn validate_key_name_with_hash() {
    assert!(validate_key_name("my#key").is_ok());
}

#[test]
fn validate_key_name_with_percent() {
    assert!(validate_key_name("my%key").is_ok());
}

#[test]
fn validate_key_name_with_at() {
    assert!(validate_key_name("my@key").is_ok());
}

#[test]
fn validate_key_name_with_exclamation() {
    assert!(validate_key_name("my!key").is_ok());
}

#[test]
fn validate_key_name_with_tilde() {
    // Tilde at start could be expanded by shell
    assert!(validate_key_name("~key").is_ok());
}

#[test]
fn validate_key_name_with_glob_chars() {
    assert!(validate_key_name("my*key").is_ok());
    assert!(validate_key_name("my?key").is_ok());
}

#[test]
fn validate_key_name_with_path_traversal_variants() {
    // Various path traversal attempts
    assert!(validate_key_name("../key").is_err());
    assert!(validate_key_name("key/..").is_err());
    assert!(validate_key_name("key/../key").is_err());
    assert!(validate_key_name("key/..").is_err());
}

#[test]
fn validate_key_name_with_backslash_traversal() {
    assert!(validate_key_name("..\\key").is_err());
    assert!(validate_key_name("key\\..").is_err());
}

// ---------------------------------------------------------------------------
// Workflow-discovered edge cases
// ---------------------------------------------------------------------------

#[test]
fn validate_key_name_null_byte_rejected() {
    // Null bytes can cause path truncation via C-level APIs
    assert!(validate_key_name("evil\0safe").is_err());
}

#[test]
fn validate_key_name_null_byte_at_start() {
    assert!(validate_key_name("\0key").is_err());
}

#[test]
fn validate_key_name_null_byte_at_end() {
    assert!(validate_key_name("key\0").is_err());
}

#[test]
fn validate_key_name_multiple_null_bytes() {
    assert!(validate_key_name("key\0\0\0").is_err());
}

// ===========================================================================
// Finding (1): passphrase must NEVER appear in ssh-keygen argv.
// change_passphrase / change_comment route through SSH_ASKPASS; the repair
// fallback does the same. These tests assert the secret is absent from the
// constructed argv and (for change_passphrase) that SSH_ASKPASS env is set.
// ===========================================================================

use std::sync::Mutex;

/// One captured [`CliRunner`] invocation: `(cmd, args, env_or_empty)`.
type CapturedCall = (String, Vec<String>, Vec<(String, String)>);

/// A [`CliRunner`] test double that records every invocation's command name,
/// argv, and (for `run_with_env`) environment, returning canned stdout.
struct CapturingRunner {
    /// Captured calls.
    calls: Mutex<Vec<CapturedCall>>,
}

impl CapturingRunner {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<CapturedCall> {
        self.calls.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl toride_ssh_core::CliRunner for CapturingRunner {
    async fn run(&self, cmd: &str, args: Vec<String>) -> toride_ssh_core::Result<String> {
        self.calls
            .lock()
            .expect("lock")
            .push((cmd.to_owned(), args, Vec::new()));
        Ok(String::new())
    }

    async fn run_with_env(
        &self,
        cmd: &str,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> toride_ssh_core::Result<String> {
        self.calls
            .lock()
            .expect("lock")
            .push((cmd.to_owned(), args, env));
        Ok(String::new())
    }

    fn tool_exists(&self, _name: &str) -> bool {
        true
    }
}

/// Build a `KeyService` backed by `runner` over a fake SSH dir. Caller owns
/// the [`SshPaths`] so the returned service borrows a stable path source.
fn service_with_runner<'a>(
    paths: &'a toride_ssh_core::SshPaths,
    runner: &'a CapturingRunner,
) -> KeyService<'a> {
    KeyService::new(paths, runner)
}

#[tokio::test]
async fn change_passphrase_omits_p_and_n_from_argv() {
    let dir = tempfile::TempDir::new().unwrap();
    let key_path = dir.path().join("id_ed25519");
    // change_passphrase checks existence; create an empty placeholder file.
    std::fs::write(&key_path, b"placeholder").unwrap();

    let runner = CapturingRunner::new();
    let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
    let svc = service_with_runner(&paths, &runner);
    svc.change_passphrase(&key_path, Some("old-secret"), Some("new-secret"))
        .await
        .expect("change_passphrase should succeed");

    let calls = runner.calls();
    assert_eq!(calls.len(), 1, "exactly one ssh-keygen call expected");
    let (cmd, args, env) = &calls[0];
    assert_eq!(cmd, "ssh-keygen");
    assert!(
        !args.iter().any(|a| a == "-P"),
        "-P (old passphrase) leaked into argv: {args:?}"
    );
    assert!(
        !args.iter().any(|a| a == "-N"),
        "-N (new passphrase) leaked into argv: {args:?}"
    );
    assert!(
        !args.contains(&"old-secret".to_owned()),
        "old passphrase value leaked into argv: {args:?}"
    );
    assert!(
        !args.contains(&"new-secret".to_owned()),
        "new passphrase value leaked into argv: {args:?}"
    );
    // Must be routed through SSH_ASKPASS.
    let askpass = env
        .iter()
        .find(|(k, _)| k == "SSH_ASKPASS")
        .map(|(_, v)| v.clone())
        .expect("SSH_ASKPASS env must be set");
    assert!(!askpass.is_empty());
    assert!(
        env.iter().any(|(k, v)| k == "SSH_ASKPASS_REQUIRE" && v == "force"),
        "SSH_ASKPASS_REQUIRE=force must be set: {env:?}"
    );
}

#[tokio::test]
async fn change_comment_omits_p_from_argv_when_passphrase_given() {
    let dir = tempfile::TempDir::new().unwrap();
    let key_path = dir.path().join("id_ed25519");
    std::fs::write(&key_path, b"placeholder").unwrap();

    let runner = CapturingRunner::new();
    let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
    let svc = service_with_runner(&paths, &runner);
    svc.change_comment(&key_path, "new-comment", Some("key-secret"))
        .await
        .expect("change_comment should succeed");

    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    let (cmd, args, env) = &calls[0];
    assert_eq!(cmd, "ssh-keygen");
    assert!(args.contains(&"-c".to_owned()));
    assert!(args.contains(&"-C".to_owned()));
    assert!(args.contains(&"new-comment".to_owned()));
    assert!(
        !args.iter().any(|a| a == "-P"),
        "-P leaked into argv: {args:?}"
    );
    assert!(
        !args.contains(&"key-secret".to_owned()),
        "passphrase value leaked into argv: {args:?}"
    );
    assert!(
        env.iter().any(|(k, _)| k == "SSH_ASKPASS"),
        "SSH_ASKPASS env must be set when a passphrase is supplied: {env:?}"
    );
}

#[tokio::test]
async fn change_comment_no_passphrase_uses_plain_run() {
    let dir = tempfile::TempDir::new().unwrap();
    let key_path = dir.path().join("id_ed25519");
    std::fs::write(&key_path, b"placeholder").unwrap();

    let runner = CapturingRunner::new();
    let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
    let svc = service_with_runner(&paths, &runner);
    svc.change_comment(&key_path, "new-comment", None)
        .await
        .expect("change_comment should succeed");

    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    let (_cmd, _args, env) = &calls[0];
    // No passphrase -> no SSH_ASKPASS wiring.
    assert!(
        !env.iter().any(|(k, _)| k == "SSH_ASKPASS"),
        "SSH_ASKPASS should not be set when no passphrase: {env:?}"
    );
}

#[tokio::test]
async fn repair_public_routes_passphrase_through_askpass_not_argv() {
    let dir = tempfile::TempDir::new().unwrap();
    let key_path = dir.path().join("id_encrypted");
    // Write a body that the in-process ssh_key parser will REJECT so the
    // code falls through to the ssh-keygen -y branch (the path under fix).
    std::fs::write(&key_path, b"not-a-valid-openssh-key").unwrap();

    let runner = CapturingRunner::new();
    // repair_public -> repair::repair_public_key is invoked via the service.
    let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
    let svc = KeyService::new(&paths, &runner);
    // The repair fallback runs `ssh-keygen -y -f <path>`; with the capturing
    // runner it returns Ok("") so the write step proceeds.
    let _ = svc
        .repair_public(&key_path, Some("repair-secret"))
        .await;
    // repair writes the .pub; ignore outcome, inspect captured calls.

    let calls = runner.calls();
    // Find the ssh-keygen -y call.
    let Some((_cmd, args, env)) = calls.iter().find(|(cmd, args, _)| {
        cmd == "ssh-keygen" && args.first() == Some(&"-y".to_owned())
    }) else {
        // The in-process path may have succeeded on some ssh_key versions
        // for arbitrary bytes; in that case assert no -P leaked anywhere.
        for (cmd, args, _env) in &calls {
            if cmd == "ssh-keygen" {
                assert!(
                    !args.iter().any(|a| a == "-P"),
                    "-P leaked into argv: {args:?}"
                );
            }
        }
        return;
    };
    assert!(
        !args.iter().any(|a| a == "-P"),
        "-P leaked into ssh-keygen -y argv: {args:?}"
    );
    assert!(
        !args.contains(&"repair-secret".to_owned()),
        "passphrase value leaked into argv: {args:?}"
    );
    assert!(
        env.iter().any(|(k, _)| k == "SSH_ASKPASS"),
        "SSH_ASKPASS env must be set for encrypted repair: {env:?}"
    );
}

/// The multi-askpass script must answer old/new/new across its three
/// invocations (the order `ssh-keygen -p` prompts in). This is the load-bearing
/// invariant for `change_passphrase` not silently re-using the old passphrase
/// as the new one.
#[cfg(unix)]
#[test]
fn multi_askpass_answers_in_order() {
    use std::os::unix::fs::PermissionsExt;
    let handler = MultiAskpassHandler::new(&["old-pass", "new-pass", "new-pass"])
        .expect("handler creation");
    let script = handler.script_path().to_path_buf();
    // The script needs execute permission.
    let mode = std::fs::metadata(&script).unwrap().permissions().mode();
    assert_ne!(mode & 0o100, 0, "multi-askpass script must be executable");
    assert_eq!(mode & 0o777, 0o700, "multi-askpass script must be 0o700");

    let run = || {
        std::process::Command::new(&script)
            .output()
            .expect("run script")
    };
    let o1 = String::from_utf8(run().stdout).unwrap();
    let o2 = String::from_utf8(run().stdout).unwrap();
    let o3 = String::from_utf8(run().stdout).unwrap();
    assert_eq!(o1.trim(), "old-pass", "first prompt must answer old");
    assert_eq!(o2.trim(), "new-pass", "second prompt must answer new");
    assert_eq!(
        o3.trim(),
        "new-pass",
        "third (confirmation) prompt must re-answer new"
    );
    // A hypothetical 4th prompt falls through to the last value.
    let o4 = String::from_utf8(run().stdout).unwrap();
    assert_eq!(o4.trim(), "new-pass");
}

/// The multi-askpass script survives passphrase values containing shell
/// metacharacters (single quotes), matching the `AskpassHandler` escaping.
#[cfg(unix)]
#[test]
fn multi_askpass_escapes_single_quotes() {
    let handler =
        MultiAskpassHandler::new(&["it's a 'secret'"]).expect("handler creation");
    let script = handler.script_path().to_path_buf();
    let out = std::process::Command::new(&script)
        .output()
        .expect("run script");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        "it's a 'secret'",
        "single quotes in passphrase must be escaped correctly"
    );
}

/// End-to-end proof that the askpass-driven `ssh-keygen -p` path (used by
/// [`KeyService::change_passphrase`]) actually rotates an encrypted key's
/// passphrase, with neither the old nor new passphrase on the argv. Mirrors
/// the existing `askpass_keygen_is_openssh_compatible` integration test.
/// Skips when `ssh-keygen` is not on PATH.
#[cfg(unix)]
#[test]
fn multi_askpass_keygen_p_rotates_passphrase_without_argv_leak() {
    let ssh_keygen_present = std::process::Command::new("ssh-keygen")
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if !ssh_keygen_present {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }

    let dir = tempfile::TempDir::new().expect("temp dir");
    let keypath = dir.path().join("chpass_key");
    let keypath_str = keypath.to_str().expect("utf-8 path").to_owned();

    // 1. Generate an encrypted key with a known passphrase (use -N here only
    //    for the *initial* generation, which is not the code path under test).
    let gen_status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f", &keypath_str, "-N", "oldpass-xyz"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn ssh-keygen generate");
    assert!(gen_status.success(), "initial key generation failed");

    // 2. Rotate the passphrase WITHOUT -P/-N, feeding old/new/new via the
    //    multi-askpass helper (exactly what change_passphrase does).
    let handler = MultiAskpassHandler::new(&["oldpass-xyz", "newpass-xyz", "newpass-xyz"])
        .expect("handler creation");
    let change = std::process::Command::new("ssh-keygen")
        .args(["-p", "-f", &keypath_str])
        .env("SSH_ASKPASS", handler.script_path())
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn ssh-keygen -p");
    assert!(
        change.status.success(),
        "ssh-keygen -p (askpass) failed: {}",
        String::from_utf8_lossy(&change.stderr)
    );

    // 3. The OLD passphrase must no longer decrypt the key.
    let old = std::process::Command::new("ssh-keygen")
        .args(["-y", "-P", "oldpass-xyz", "-f", &keypath_str])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn verify-old");
    assert!(
        !old.success(),
        "old passphrase should no longer work after rotation"
    );

    // 4. The NEW passphrase must decrypt the key.
    let new = std::process::Command::new("ssh-keygen")
        .args(["-y", "-P", "newpass-xyz", "-f", &keypath_str])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn verify-new");
    assert!(
        new.success(),
        "new passphrase should decrypt the rotated key"
    );
}

// ===========================================================================
// Finding (2): filter_config_lines / remove_from_config coverage.
// ===========================================================================

fn filtered(input: &str, ssh_dir: &str, key_name: &str) -> String {
    filter_config_lines(input, ssh_dir, key_name)
}

#[test]
fn filter_removes_identityfile_tilde_form() {
    let input = "Host example\n    IdentityFile ~/.ssh/id_ed25519\n    User foo\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(
        !out.contains("IdentityFile"),
        "IdentityFile tilde line should be removed: {out}"
    );
    assert!(out.contains("Host example"));
    assert!(out.contains("User foo"));
}

#[test]
fn filter_removes_identityfile_absolute_form() {
    let input =
        "Host example\n    IdentityFile /home/u/.ssh/id_ed25519\n    User foo\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(
        !out.contains("IdentityFile"),
        "IdentityFile absolute line should be removed: {out}"
    );
}

#[test]
fn filter_removes_identityfile_single_quoted() {
    let input = "IdentityFile '~/.ssh/id_ed25519'\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(out.trim().is_empty(), "single-quoted tilde value removed: {out}");
}

#[test]
fn filter_removes_identityfile_double_quoted() {
    let input = "IdentityFile \"/home/u/.ssh/id_ed25519\"\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(out.trim().is_empty(), "double-quoted absolute value removed: {out}");
}

#[test]
fn filter_removes_certificatefile_companion() {
    let input = "Host example\n    IdentityFile ~/.ssh/id_ed25519\n    CertificateFile ~/.ssh/id_ed25519-cert.pub\n    User foo\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(
        !out.contains("CertificateFile"),
        "CertificateFile companion should be removed: {out}"
    );
    assert!(!out.contains("IdentityFile"));
    assert!(out.contains("User foo"));
}

#[test]
fn filter_preserves_unrelated_identityfile() {
    // A different key must be left in place.
    let input = "Host a\n    IdentityFile ~/.ssh/other_key\n    IdentityFile ~/.ssh/id_ed25519\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(
        out.contains("~/.ssh/other_key"),
        "unrelated IdentityFile must be preserved: {out}"
    );
    assert!(!out.contains("id_ed25519"));
}

#[test]
fn filter_preserves_substring_only_lines() {
    // A line that merely CONTAINS the name (e.g. a Host alias or comment) but
    // is not an IdentityFile for this key must be preserved.
    let input = "Host id_ed25519-backup\n   HostName id_ed25519.example.com\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert_eq!(
        out, input,
        "lines that only mention the name as a substring must be untouched"
    );
}

#[test]
fn filter_keyword_is_case_insensitive() {
    let input = "identityfile ~/.ssh/id_ed25519\nIDENTITYFILE ~/.ssh/id_ed25519\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(
        out.trim().is_empty(),
        "case-insensitive keyword match should drop both lines: {out}"
    );
}

#[test]
fn filter_preserves_crlf_line_endings() {
    let input = "Host a\r\n    IdentityFile ~/.ssh/id_ed25519\r\n    User foo\r\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(
        out.contains("\r\n"),
        "CRLF line endings must be preserved: {out:?}"
    );
    assert!(!out.contains("IdentityFile"));
    assert!(out.contains("User foo"));
}

#[test]
fn filter_preserves_lf_line_endings() {
    let input = "Host a\n    IdentityFile ~/.ssh/id_ed25519\n    User foo\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(
        !out.contains("\r\n"),
        "no stray CRLF should be introduced: {out:?}"
    );
    assert!(out.contains("User foo"));
}

#[test]
fn filter_noop_when_key_not_referenced() {
    let input = "Host a\n    IdentityFile ~/.ssh/other\n    User foo\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert_eq!(
        out, input,
        "content must be byte-identical when the key is not referenced"
    );
}

#[test]
fn filter_removes_bare_name_identityfile() {
    // Some configs reference just the bare key name (resolved against ssh_dir).
    let input = "IdentityFile id_ed25519\n";
    let out = filtered(input, "/home/u/.ssh", "id_ed25519");
    assert!(out.trim().is_empty(), "bare-name IdentityFile should be removed: {out}");
}

#[tokio::test]
async fn remove_from_config_noop_leaves_file_byte_identical() {
    let dir = tempfile::TempDir::new().unwrap();
    // Build an ssh dir that contains a config that does NOT reference the key.
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let config = ssh_dir.join("config");
    let original = "Host a\n    IdentityFile ~/.ssh/other\n    User foo\n";
    std::fs::write(&config, original.as_bytes()).unwrap();

    let paths = toride_ssh_core::SshPaths::with_dir(&ssh_dir);
    // remove_from_config is private; exercise it via KeyService::delete with all
    // removal flags off except remove_from_config. That also requires the key
    // file to exist for the early branch; instead call the delete path that
    // only does config cleanup by deleting a present key file.
    let key_path = ssh_dir.join("id_ed25519");
    std::fs::write(&key_path, b"private").unwrap();
    std::fs::write(ssh_dir.join("id_ed25519.pub"), b"pub").unwrap();

    let runner = CapturingRunner::new();
    let svc = KeyService::new(&paths, &runner);
    let params = toride_ssh_core::KeyDeleteParams {
        name: "id_ed25519".to_owned(),
        remove_public: false,
        remove_certificate: false,
        remove_from_agent: false,
        remove_from_config: true,
        backup: false,
    };
    svc.delete(params).await.expect("delete should succeed");

    let after = std::fs::read(&config).unwrap();
    assert_eq!(
        after, original.as_bytes(),
        "config must be byte-identical when key is not referenced"
    );
}

#[tokio::test]
async fn remove_from_config_strips_referenced_line_and_writes_atomically() {
    let dir = tempfile::TempDir::new().unwrap();
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let config = ssh_dir.join("config");
    let original =
        "Host a\n    IdentityFile ~/.ssh/id_ed25519\n    User foo\n";
    std::fs::write(&config, original.as_bytes()).unwrap();

    let paths = toride_ssh_core::SshPaths::with_dir(&ssh_dir);
    let key_path = ssh_dir.join("id_ed25519");
    std::fs::write(&key_path, b"private").unwrap();

    let runner = CapturingRunner::new();
    let svc = KeyService::new(&paths, &runner);
    let params = toride_ssh_core::KeyDeleteParams {
        name: "id_ed25519".to_owned(),
        remove_public: false,
        remove_certificate: false,
        remove_from_agent: false,
        remove_from_config: true,
        backup: false,
    };
    svc.delete(params).await.expect("delete should succeed");

    let after = std::fs::read_to_string(&config).unwrap();
    assert!(!after.contains("IdentityFile"), "IdentityFile removed: {after}");
    assert!(after.contains("User foo"), "other lines preserved: {after}");
    // No leftover temp file in the ssh dir.
    let leftovers = std::fs::read_dir(&ssh_dir)
        .unwrap()
        .filter_map(std::result::Result::<_, std::io::Error>::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".config.tmp.")
        })
        .count();
    assert_eq!(leftovers, 0, "temp config file must be cleaned up");
}
