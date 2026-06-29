//! CLI argument definitions via clap.
//!
//! Provides the command-line interface for the `toride-users` binary
//! or integration with the main `toride` CLI.
//!
//! [`Cli::dispatch`] maps each [`Commands`] variant to the corresponding
//! [`UsersClient`](crate::client::UsersClient) operation. It takes the client
//! by reference so a caller can inject a `UsersClient::with_paths(tmp)` for
//! testing without touching the real `/etc` tree.

use clap::{Parser, Subcommand};

use crate::Result;
use crate::client::UsersClient;

/// Toride users management CLI.
#[derive(Debug, Parser)]
#[command(
    name = "toride-users",
    version,
    about = "OS-level user and access control management"
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Parse `std::env::args_os()` and run the command against a production
    /// [`UsersClient`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if argument parsing fails or the dispatched
    /// command fails.
    pub fn run() -> Result<()> {
        let cli = Self::parse();
        let client = UsersClient::new();
        cli.dispatch(&client, &mut std::io::stdout())
    }

    /// Execute the parsed command against a [`UsersClient`], writing any
    /// human-readable output to `writer`.
    ///
    /// Taking the client by reference (rather than constructing it internally)
    /// lets tests inject a `UsersClient::with_paths(tmp)` so dispatch is
    /// exercised against a temp `/etc` tree instead of the real host.
    ///
    /// # Errors
    ///
    /// Propagates any [`crate::Error`] from the underlying operation.
    pub fn dispatch<W: std::io::Write>(&self, client: &UsersClient, writer: &mut W) -> Result<()> {
        let cmd = &self.command;
        tracing::debug!(?cmd, "dispatching toride-users command");
        match cmd {
            Commands::Create {
                username,
                shell,
                groups,
                sudo,
                totp,
            } => {
                client.user().create(username, shell, groups, None)?;
                if *sudo {
                    client.sudo().grant(username, false)?;
                }
                if *totp {
                    // `enroll` returns the `google-authenticator` output, which
                    // contains the TOTP secret and one-time scratch codes.
                    // Discarding it (the old `let _ = ...`) would lock the user
                    // out: the `.google_authenticator` file is created but the
                    // secret is never shown to anyone. Surface it to the caller
                    // the same way the dedicated `totp-enroll` command does.
                    let totp_out = client.totp().enroll(username)?;
                    writeln!(writer, "TOTP enrolled for '{username}':").ok();
                    // Propagate the secret write: a broken writer here would
                    // otherwise silently lose the ONLY copy of the secret and
                    // lock the user out (the `.google_authenticator` file is
                    // already created). The informational lines stay best-effort.
                    writeln!(writer, "{totp_out}")?;
                    writeln!(writer, "Store the secret and scratch codes above securely.").ok();
                }
                writeln!(writer, "created user '{username}'").ok();
            }
            Commands::Delete {
                username,
                remove_home,
            } => {
                client.user().delete(username, *remove_home)?;
                writeln!(writer, "deleted user '{username}'").ok();
            }
            Commands::SudoGrant { username, nopasswd } => {
                client.sudo().grant(username, *nopasswd)?;
                writeln!(writer, "granted sudo to '{username}' (nopasswd={nopasswd})").ok();
            }
            Commands::SudoRevoke { username } => {
                client.sudo().revoke(username)?;
                writeln!(writer, "revoked sudo from '{username}'").ok();
            }
            Commands::TotpEnroll { username } => {
                // `cli` implies `client`, which compiles `totp::enroll_totp`.
                let out = client.totp().enroll(username)?;
                // This command's whole purpose is to surface the secret;
                // propagate the write so a broken writer fails loudly rather
                // than silently losing the only copy of the secret.
                writeln!(writer, "{out}")?;
            }
            Commands::TotpRemove { username } => {
                client.totp().remove(username)?;
                writeln!(writer, "removed TOTP for '{username}'").ok();
            }
            Commands::Lock { username } => {
                client.password().lock(username)?;
                writeln!(writer, "locked account '{username}'").ok();
            }
            Commands::Unlock { username } => {
                client.password().unlock(username)?;
                writeln!(writer, "unlocked account '{username}'").ok();
            }
            Commands::Doctor { scope } => {
                #[cfg(feature = "doctor")]
                {
                    let scope = parse_doctor_scope(scope)?;
                    let doctor = crate::doctor::Doctor::with_paths(client.paths().clone());
                    let report = doctor.run(&scope)?;
                    if report.is_empty() {
                        writeln!(writer, "no findings").ok();
                    } else {
                        for finding in &report.findings {
                            writeln!(
                                writer,
                                "[{}] {} — {}",
                                finding.severity, finding.id, finding.title
                            )
                            .ok();
                        }
                    }
                }
                #[cfg(not(feature = "doctor"))]
                {
                    let _ = scope;
                    return Err(crate::Error::Other(
                        "the 'doctor' feature is required for the `doctor` command".into(),
                    ));
                }
            }
            Commands::Info { username } => {
                dispatch_info(client, username, writer)?;
            }
        }
        Ok(())
    }
}

/// Body of the `Info` command: read-only lookup of a user's account state.
///
/// Pulled out of [`Cli::dispatch`] so the match stays readable and under
/// clippy's line budget. Optional shadow/TOTP reads degrade to defaults.
fn dispatch_info<W: std::io::Write>(
    client: &UsersClient,
    username: &str,
    writer: &mut W,
) -> Result<()> {
    if !client.user().exists(username)? {
        writeln!(writer, "user '{username}' not found").ok();
        return Ok(());
    }
    let uid = client.user().uid(username)?;
    let shell = client.user().get_shell(username)?;
    let sudo = client.sudo().has_sudo(username)?;
    let locked = client.password().is_locked(username).unwrap_or(false);
    let totp = client.totp().is_configured(username).unwrap_or(false);
    writeln!(writer, "user: {username}").ok();
    writeln!(writer, "uid: {uid}").ok();
    writeln!(writer, "shell: {shell}").ok();
    writeln!(writer, "sudo: {sudo}").ok();
    writeln!(writer, "locked: {locked}").ok();
    writeln!(writer, "totp: {totp}").ok();
    Ok(())
}

/// Parse a `DoctorScope` name from the CLI `--scope` string.
///
/// Accepts the canonical names (`all`, `accounts`, `sudo`, `pam`,
/// `password-policy`). Unknown values return an [`crate::Error::Other`].
#[cfg(feature = "doctor")]
fn parse_doctor_scope(s: &str) -> Result<crate::doctor::DoctorScope> {
    use crate::doctor::DoctorScope;
    Ok(match s {
        "all" => DoctorScope::All,
        "accounts" => DoctorScope::Accounts,
        "sudo" => DoctorScope::Sudo,
        "pam" => DoctorScope::Pam,
        "password-policy" | "password_policy" | "passwordpolicy" => DoctorScope::PasswordPolicy,
        other => {
            return Err(crate::Error::Other(format!(
                "unknown doctor scope '{other}' (expected: all, accounts, sudo, pam, \
                 password-policy)"
            )));
        }
    })
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create a new user account.
    Create {
        /// Username for the new account.
        username: String,
        /// Login shell.
        #[arg(long, default_value = "/usr/bin/bash")]
        shell: String,
        /// Supplementary groups (comma-separated).
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        /// Grant sudo access.
        #[arg(long)]
        sudo: bool,
        /// Enable TOTP/2FA.
        #[arg(long)]
        totp: bool,
    },

    /// Delete a user account.
    Delete {
        /// Username to delete.
        username: String,
        /// Remove the home directory.
        #[arg(long)]
        remove_home: bool,
    },

    /// Grant sudo access to a user.
    SudoGrant {
        /// Username.
        username: String,
        /// Grant passwordless sudo (NOPASSWD).
        #[arg(long)]
        nopasswd: bool,
    },

    /// Revoke sudo access from a user.
    SudoRevoke {
        /// Username.
        username: String,
    },

    /// Enroll a user in TOTP/2FA.
    TotpEnroll {
        /// Username.
        username: String,
    },

    /// Remove TOTP/2FA for a user.
    TotpRemove {
        /// Username.
        username: String,
    },

    /// Lock a user account.
    Lock {
        /// Username.
        username: String,
    },

    /// Unlock a user account.
    Unlock {
        /// Username.
        username: String,
    },

    /// Run diagnostic checks.
    Doctor {
        /// Scope of checks to run.
        #[arg(long, default_value = "all")]
        scope: String,
    },

    /// Show user information.
    Info {
        /// Username to inspect.
        username: String,
    },
}

/// Parse CLI arguments from strings (useful for testing).
///
/// # Errors
///
/// Returns an error if the arguments cannot be parsed.
pub fn parse_args<I, S>(args: I) -> clap::error::Result<Cli>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::UsersClient;
    use crate::paths::UserPaths;
    use tempfile::TempDir;

    /// Build a `UsersClient` rooted at a fresh temp dir, pre-populated with a
    /// minimal passwd/shadow/group so the read-only commands (Info, Doctor)
    /// have real data to work against without touching the host's `/etc`.
    fn temp_client() -> (TempDir, UsersClient) {
        let dir = TempDir::new().expect("tempdir");
        let paths = UserPaths::with_base(&dir.path().to_path_buf());
        std::fs::write(
            &paths.passwd,
            "root:x:0:0:root:/root:/bin/bash\n\
             alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        )
        .expect("write passwd");
        std::fs::write(
            &paths.shadow,
            "root:$6$xx::0:99999:7:::\nalice:$6$yy::0:99999:7:::\n",
        )
        .expect("write shadow");
        std::fs::write(&paths.group, "root:x:0:\nalice:x:1000:\nsudo:x:27:\n")
            .expect("write group");
        let client = UsersClient::with_paths(paths);
        (dir, client)
    }

    fn dispatch_collect(client: &UsersClient, cmd: Commands) -> (String, Result<()>) {
        let cli = Cli { command: cmd };
        let mut out = std::io::Cursor::new(Vec::<u8>::new());
        let res = cli.dispatch(client, &mut out);
        let text = String::from_utf8(out.into_inner()).expect("utf8");
        (text, res)
    }

    // ---- argument parsing: each variant parses to the expected Commands ----

    #[test]
    fn parse_create_with_defaults_and_flags() {
        let cli = parse_args(["toride-users", "create", "deployer"]).expect("parse create");
        match cli.command {
            Commands::Create {
                username,
                shell,
                groups,
                sudo,
                totp,
            } => {
                assert_eq!(username, "deployer");
                assert_eq!(shell, "/usr/bin/bash", "shell default should apply");
                assert!(groups.is_empty());
                assert!(!sudo);
                assert!(!totp);
            }
            other => panic!("expected Create, got {other:?}"),
        }
    }

    #[test]
    fn parse_create_with_groups_and_sudo() {
        let cli = parse_args([
            "toride-users",
            "create",
            "deployer",
            "--shell",
            "/usr/sbin/nologin",
            "--groups",
            "sudo,docker",
            "--sudo",
            "--totp",
        ])
        .expect("parse create");
        match cli.command {
            Commands::Create {
                username,
                shell,
                groups,
                sudo,
                totp,
            } => {
                assert_eq!(username, "deployer");
                assert_eq!(shell, "/usr/sbin/nologin");
                assert_eq!(groups, vec!["sudo".to_owned(), "docker".to_owned()]);
                assert!(sudo);
                assert!(totp);
            }
            other => panic!("expected Create, got {other:?}"),
        }
    }

    #[test]
    fn parse_delete_remove_home() {
        let cli = parse_args(["toride-users", "delete", "bob", "--remove-home"]).expect("parse");
        match cli.command {
            Commands::Delete {
                username,
                remove_home,
            } => {
                assert_eq!(username, "bob");
                assert!(remove_home);
            }
            other => panic!("expected Delete, got {other:?}"),
        }
    }

    #[test]
    fn parse_sudo_grant_nopasswd() {
        let cli = parse_args(["toride-users", "sudo-grant", "alice", "--nopasswd"]).expect("parse");
        match cli.command {
            Commands::SudoGrant { username, nopasswd } => {
                assert_eq!(username, "alice");
                assert!(nopasswd);
            }
            other => panic!("expected SudoGrant, got {other:?}"),
        }
    }

    #[test]
    fn parse_doctor_default_scope_is_all() {
        let cli = parse_args(["toride-users", "doctor"]).expect("parse doctor");
        match cli.command {
            Commands::Doctor { scope } => assert_eq!(scope, "all"),
            other => panic!("expected Doctor, got {other:?}"),
        }
    }

    #[test]
    fn parse_doctor_custom_scope() {
        let cli =
            parse_args(["toride-users", "doctor", "--scope", "password-policy"]).expect("parse");
        match cli.command {
            Commands::Doctor { scope } => assert_eq!(scope, "password-policy"),
            other => panic!("expected Doctor, got {other:?}"),
        }
    }

    #[test]
    fn parse_info() {
        let cli = parse_args(["toride-users", "info", "alice"]).expect("parse info");
        match cli.command {
            Commands::Info { username } => assert_eq!(username, "alice"),
            other => panic!("expected Info, got {other:?}"),
        }
    }

    // ---- dispatch: read-only commands exercised against a temp /etc tree ----

    /// `Info` for an existing user reads passwd (uid, shell), and degrades the
    /// optional shadow/totp reads (no real `.google_authenticator` here) to
    /// defaults. The output must name the user and uid.
    #[test]
    fn dispatch_info_existing_user() {
        let (_dir, client) = temp_client();
        let (text, res) = dispatch_collect(
            &client,
            Commands::Info {
                username: "alice".to_owned(),
            },
        );
        res.expect("info dispatch should succeed");
        assert!(text.contains("user: alice"), "output: {text}");
        assert!(text.contains("uid: 1000"), "output: {text}");
        assert!(text.contains("shell: /bin/bash"), "output: {text}");
        // alice is not in the sudo group here.
        assert!(text.contains("sudo: false"), "output: {text}");
    }

    /// `Info` for a missing user does not error; it reports "not found".
    #[test]
    fn dispatch_info_missing_user() {
        let (_dir, client) = temp_client();
        let (text, res) = dispatch_collect(
            &client,
            Commands::Info {
                username: "ghost".to_owned(),
            },
        );
        res.expect("missing-user info should not error");
        assert!(text.contains("not found"), "output: {text}");
    }

    /// `Doctor` dispatch runs the doctor against the temp tree and emits
    /// findings. We populate `login.defs` WITHOUT `PASS_*_DAYS` so the
    /// password-policy check is entered (the file exists) and both the
    /// no-max-days and no-min-days findings fire.
    #[cfg(feature = "doctor")]
    #[test]
    fn dispatch_doctor_emits_findings() {
        let dir = TempDir::new().expect("tempdir");
        let paths = UserPaths::with_base(&dir.path().to_path_buf());
        std::fs::write(
            &paths.passwd,
            "root:x:0:0:root:/root:/bin/bash\n\
             alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        )
        .expect("write passwd");
        std::fs::write(
            &paths.shadow,
            "root:$6$xx::0:99999:7:::\nalice:$6$yy::0:99999:7:::\n",
        )
        .expect("write shadow");
        std::fs::write(&paths.group, "root:x:0:\nalice:x:1000:\n").expect("write group");
        // login.defs exists but has NEITHER PASS_MAX_DAYS nor PASS_MIN_DAYS.
        std::fs::write(&paths.login_defs, "# no policy here\n").expect("write login.defs");
        let client = UsersClient::with_paths(paths);

        let (text, res) = dispatch_collect(
            &client,
            Commands::Doctor {
                scope: "password-policy".to_owned(),
            },
        );
        res.expect("doctor dispatch should succeed");
        assert!(
            text.contains("password-policy.no-max-days"),
            "expected no-max-days finding in output: {text}"
        );
        assert!(
            text.contains("password-policy.no-min-days"),
            "expected no-min-days finding in output: {text}"
        );
    }

    /// `Doctor` against a clean tree reports "no findings".
    #[cfg(feature = "doctor")]
    #[test]
    fn dispatch_doctor_no_findings() {
        let dir = TempDir::new().expect("tempdir");
        let paths = UserPaths::with_base(&dir.path().to_path_buf());
        // Populate login.defs so no password-policy findings fire.
        std::fs::write(&paths.login_defs, "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\n")
            .expect("login.defs");
        // passwd + shadow that trigger no empty-password / uid-0 findings.
        std::fs::write(&paths.passwd, "root:x:0:0:root:/root:/bin/bash\n").expect("passwd");
        std::fs::write(&paths.shadow, "root:$6$xx::0:99999:7:::\n").expect("shadow");
        // No sudoers / sudoers.d -> no NOPASSWD findings.
        let client = UsersClient::with_paths(paths);
        let (text, res) = dispatch_collect(
            &client,
            Commands::Doctor {
                scope: "all".to_owned(),
            },
        );
        res.expect("doctor dispatch should succeed");
        // sshd_config absent -> no root-login finding; sudoers absent; pam.d/sshd
        // absent -> no sshd-no-totp finding. The only possible remaining is the
        // sudo group scan, but there is no sudo group here.
        assert!(
            text.contains("no findings") || text.trim().is_empty(),
            "expected no findings on a clean tree, got: {text}"
        );
    }

    /// An invalid `--scope` value surfaces an honest error rather than
    /// silently running the default scope.
    #[cfg(feature = "doctor")]
    #[test]
    fn dispatch_doctor_invalid_scope_errors() {
        let (_dir, client) = temp_client();
        let (text, res) = dispatch_collect(
            &client,
            Commands::Doctor {
                scope: "bogus".to_owned(),
            },
        );
        let err = res.expect_err("invalid scope should error");
        assert!(
            matches!(err, crate::Error::Other(_)),
            "expected Other error, got {err:?}"
        );
        assert!(err.to_string().contains("unknown doctor scope 'bogus'"));
        // No doctor output was produced.
        assert!(text.is_empty(), "no output before error: {text}");
    }

    /// `parse_doctor_scope` accepts the canonical names and the underscore
    /// spelling of `password-policy`.
    #[cfg(feature = "doctor")]
    #[test]
    fn parse_doctor_scope_canonical_names() {
        use crate::doctor::DoctorScope;
        assert_eq!(parse_doctor_scope("all").unwrap(), DoctorScope::All);
        assert_eq!(
            parse_doctor_scope("accounts").unwrap(),
            DoctorScope::Accounts
        );
        assert_eq!(parse_doctor_scope("sudo").unwrap(), DoctorScope::Sudo);
        assert_eq!(parse_doctor_scope("pam").unwrap(), DoctorScope::Pam);
        assert_eq!(
            parse_doctor_scope("password-policy").unwrap(),
            DoctorScope::PasswordPolicy
        );
        assert_eq!(
            parse_doctor_scope("password_policy").unwrap(),
            DoctorScope::PasswordPolicy
        );
        assert!(parse_doctor_scope("nonsense").is_err());
    }

    /// Dispatch surfaces a missing required positional as a clap error.
    #[test]
    fn parse_missing_subcommand_errors() {
        assert!(parse_args(["toride-users"]).is_err());
    }

    /// When the `doctor` feature is OFF, the `doctor` command must NOT silently
    /// succeed (which would mislead an operator into thinking checks ran). It
    /// returns an honest error naming the missing feature.
    #[cfg(not(feature = "doctor"))]
    #[test]
    fn dispatch_doctor_without_feature_errors_honestly() {
        let (_dir, client) = temp_client();
        let (text, res) = dispatch_collect(
            &client,
            Commands::Doctor {
                scope: "all".to_owned(),
            },
        );
        let err = res.expect_err("doctor without feature should error");
        assert!(
            matches!(err, crate::Error::Other(_)),
            "expected Other error, got {err:?}"
        );
        assert!(
            err.to_string().contains("doctor"),
            "error should name the doctor feature: {err}"
        );
        assert!(text.is_empty(), "no output before error: {text}");
    }
}
