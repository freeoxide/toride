//! Comprehensive tests for the [`client::Fail2BanClient`] module.
//!
//! Every test uses [`FakeRunner`] so no real `fail2ban-client` binary is
//! required.  Responses are injected via [`FakeRunner::with_response`] and
//! verified through both return values and the call log.

#[cfg(test)]
#[allow(
    clippy::module_inception,
    reason = "conventional inner test module name"
)]
mod tests {
    use std::path::PathBuf;

    use crate::client::Fail2BanClient;
    use crate::command::{CommandOutput, FakeRunner};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    const BIN: &str = "/usr/bin/fail2ban-client";

    fn binary() -> PathBuf {
        PathBuf::from(BIN)
    }

    fn success(stdout: &str) -> CommandOutput {
        CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        }
    }

    fn failure(stderr: &str, code: i32) -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: stderr.to_string(),
            exit_code: Some(code),
            success: false,
        }
    }

    fn failure_no_stderr(code: i32) -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(code),
            success: false,
        }
    }

    fn failure_no_exit(stderr: &str) -> CommandOutput {
        CommandOutput {
            stdout: String::new(),
            stderr: stderr.to_string(),
            exit_code: None,
            success: false,
        }
    }

    // ===================================================================
    // Construction
    // ===================================================================

    #[test]
    fn with_binary_sets_the_binary_path() {
        let fake = FakeRunner::new();
        let bin = PathBuf::from("/custom/path/fail2ban-client");
        let client = Fail2BanClient::with_binary(&fake, bin.clone());
        assert_eq!(client.binary, bin);
    }

    #[test]
    fn with_binary_preserves_runner_reference() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], success("Server replied: pong"));
        let client = Fail2BanClient::with_binary(&fake, binary());
        // Verify the runner works by calling a method.
        assert!(client.ping().is_ok());
    }

    // ===================================================================
    // ping
    // ===================================================================

    #[test]
    fn ping_succeeds_on_pong() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], success("Server replied: pong"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.ping().is_ok());
    }

    #[test]
    fn ping_calls_correct_args() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], success("Server replied: pong"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.ping().unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, BIN);
        assert_eq!(calls[0].1, vec!["ping"]);
    }

    #[test]
    fn ping_returns_unit_on_success() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], success("pong"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ping();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ());
    }

    // ===================================================================
    // version
    // ===================================================================

    #[test]
    fn version_parses_version_string() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--version"], success("Fail2Ban v1.1.0\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let ver = client.version().unwrap();
        assert_eq!(ver, "Fail2Ban v1.1.0");
    }

    #[test]
    fn version_trims_whitespace() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--version"], success("  Fail2Ban v0.11.2  \n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let ver = client.version().unwrap();
        assert_eq!(ver, "Fail2Ban v0.11.2");
    }

    #[test]
    fn version_returns_first_line_only() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["--version"],
            success("Fail2Ban v1.0.2\nCopyright 2004-2022\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let ver = client.version().unwrap();
        assert_eq!(ver, "Fail2Ban v1.0.2");
        assert!(!ver.contains("Copyright"));
    }

    #[test]
    fn version_handles_empty_output() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--version"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let ver = client.version().unwrap();
        assert_eq!(ver, "");
    }

    // ===================================================================
    // test_config
    // ===================================================================

    #[test]
    fn test_config_succeeds_on_ok() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--test"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.test_config().is_ok());
    }

    #[test]
    fn test_config_fails_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["--test"],
            failure("ERROR  found no accessible config files", 255),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.test_config();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_calls_correct_args() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--test"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.test_config().unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["--test"]);
    }

    // ===================================================================
    // reload
    // ===================================================================

    #[test]
    fn reload_succeeds() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["reload"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.reload().is_ok());
    }

    #[test]
    fn reload_calls_correct_args() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["reload"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.reload().unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["reload"]);
    }

    // ===================================================================
    // reload_jail
    // ===================================================================

    #[test]
    fn reload_jail_succeeds() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["reload", "sshd"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.reload_jail("sshd").is_ok());
    }

    #[test]
    fn reload_jail_passes_jail_name() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["reload", "nginx"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.reload_jail("nginx").unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["reload", "nginx"]);
    }

    #[test]
    fn reload_jail_with_complex_name() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["reload", "my-custom-jail"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.reload_jail("my-custom-jail").unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["reload", "my-custom-jail"]);
    }

    // ===================================================================
    // restart_jail
    // ===================================================================

    #[test]
    fn restart_jail_without_unban_flag() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["restart", "sshd"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.restart_jail("sshd", false).unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["restart", "sshd"]);
    }

    #[test]
    fn restart_jail_with_unban_flag() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["restart", "sshd", "--unban"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.restart_jail("sshd", true).unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["restart", "sshd", "--unban"]);
    }

    // ===================================================================
    // status
    // ===================================================================

    #[test]
    fn status_returns_raw_output() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["status"],
            success("Status\n|- Number of jail:      2\n`- Jail list:   sshd, nginx\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let status = client.status().unwrap();
        assert!(status.contains("sshd"));
        assert!(status.contains("nginx"));
        assert!(status.contains("Number of jail"));
    }

    #[test]
    fn status_trims_trailing_whitespace() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["status"],
            success("Status\n|- Number of jail: 0\n\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let status = client.status().unwrap();
        assert!(!status.ends_with('\n'));
    }

    #[test]
    fn status_calls_correct_args() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["status"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.status().unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["status"]);
    }

    // ===================================================================
    // status_jail
    // ===================================================================

    #[test]
    fn status_jail_returns_raw_output() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["status", "sshd"],
            success(
                "Status for the jail: sshd\n|- Filter\n|  |- Currently failed: 0\n|  |- Total failed:     0\n",
            ),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let status = client.status_jail("sshd").unwrap();
        assert!(status.contains("sshd"));
        assert!(status.contains("Currently failed"));
    }

    #[test]
    fn status_jail_passes_jail_name() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["status", "apache"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.status_jail("apache").unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["status", "apache"]);
    }

    #[test]
    fn status_jail_trims_output() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["status", "sshd"],
            success("Status for the jail: sshd\n   \n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let status = client.status_jail("sshd").unwrap();
        // The output is trimmed, so trailing whitespace and newlines are removed.
        assert_eq!(status, "Status for the jail: sshd");
    }

    // ===================================================================
    // statistics
    // ===================================================================

    #[test]
    fn statistics_delegates_to_status() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["status"],
            success("Status\n|- Number of jail:      3\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let stats = client.statistics().unwrap();
        assert!(stats.contains("Number of jail"));
    }

    #[test]
    fn statistics_records_status_call() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["status"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.statistics().unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["status"]);
    }

    // ===================================================================
    // banned
    // ===================================================================

    #[test]
    fn banned_returns_raw_output_when_empty() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["banned"], success("No banned IPs found.\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.banned().unwrap();
        assert!(result.contains("No banned IPs"));
    }

    #[test]
    fn banned_returns_raw_output_with_ips() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["banned"],
            success("192.168.1.1   sshd\n10.0.0.5      nginx\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.banned().unwrap();
        assert!(result.contains("192.168.1.1"));
        assert!(result.contains("10.0.0.5"));
    }

    #[test]
    fn banned_trims_output() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["banned"], success("No banned IPs found.\n\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.banned().unwrap();
        assert_eq!(result, "No banned IPs found.");
    }

    // ===================================================================
    // banned_ip
    // ===================================================================

    #[test]
    fn banned_ip_passes_ip_arg() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["banned", "1.2.3.4"],
            success("1.2.3.4        sshd: [active]\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.banned_ip("1.2.3.4").unwrap();
        assert!(result.contains("1.2.3.4"));

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["banned", "1.2.3.4"]);
    }

    #[test]
    fn banned_ip_not_banned() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["banned", "5.6.7.8"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.banned_ip("5.6.7.8").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn banned_ip_with_ipv6() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["banned", "::1"],
            success("::1            sshd: [active]\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.banned_ip("::1").unwrap();
        assert!(result.contains("::1"));
    }

    // ===================================================================
    // ban_ip
    // ===================================================================

    #[test]
    fn ban_ip_constructs_correct_command() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["set", "sshd", "banip", "1.2.3.4"], success("1"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.ban_ip("sshd", "1.2.3.4").unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["set", "sshd", "banip", "1.2.3.4"]);
    }

    #[test]
    fn ban_ip_returns_unit_on_success() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["set", "sshd", "banip", "10.0.0.1"], success("1"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ban_ip("sshd", "10.0.0.1");
        assert_eq!(result.unwrap(), ());
    }

    #[test]
    fn ban_ip_different_jails() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["set", "nginx", "banip", "192.168.0.1"], success("1"));
        fake.with_response(
            BIN,
            &["set", "postfix", "banip", "172.16.0.1"],
            success("1"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.ban_ip("nginx", "192.168.0.1").unwrap();
        client.ban_ip("postfix", "172.16.0.1").unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, vec!["set", "nginx", "banip", "192.168.0.1"]);
        assert_eq!(calls[1].1, vec!["set", "postfix", "banip", "172.16.0.1"]);
    }

    // ===================================================================
    // unban_ip
    // ===================================================================

    #[test]
    fn unban_ip_constructs_correct_command() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["set", "sshd", "unbanip", "1.2.3.4"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.unban_ip("sshd", "1.2.3.4").unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["set", "sshd", "unbanip", "1.2.3.4"]);
    }

    #[test]
    fn unban_ip_returns_unit_on_success() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["set", "sshd", "unbanip", "10.0.0.1"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.unban_ip("sshd", "10.0.0.1");
        assert_eq!(result.unwrap(), ());
    }

    // ===================================================================
    // add_ignore_ip
    // ===================================================================

    #[test]
    fn add_ignore_ip_constructs_correct_command() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["set", "sshd", "addignoreip", "10.0.0.0/8"],
            success(""),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.add_ignore_ip("sshd", "10.0.0.0/8").unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["set", "sshd", "addignoreip", "10.0.0.0/8"]);
    }

    #[test]
    fn add_ignore_ip_with_plain_ip() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["set", "sshd", "addignoreip", "192.168.1.100"],
            success(""),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.add_ignore_ip("sshd", "192.168.1.100").unwrap();

        let calls = fake.calls();
        assert_eq!(
            calls[0].1,
            vec!["set", "sshd", "addignoreip", "192.168.1.100"]
        );
    }

    // ===================================================================
    // remove_ignore_ip
    // ===================================================================

    #[test]
    fn remove_ignore_ip_constructs_correct_command() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["set", "sshd", "delignoreip", "10.0.0.0/8"],
            success(""),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.remove_ignore_ip("sshd", "10.0.0.0/8").unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["set", "sshd", "delignoreip", "10.0.0.0/8"]);
    }

    #[test]
    fn remove_ignore_ip_with_plain_ip() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["set", "sshd", "delignoreip", "192.168.1.100"],
            success(""),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.remove_ignore_ip("sshd", "192.168.1.100").unwrap();

        let calls = fake.calls();
        assert_eq!(
            calls[0].1,
            vec!["set", "sshd", "delignoreip", "192.168.1.100"]
        );
    }

    // ===================================================================
    // get_logtarget
    // ===================================================================

    #[test]
    fn get_logtarget_returns_trimmed_output() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["get", "logtarget"],
            success("/var/log/fail2ban.log\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let target = client.get_logtarget().unwrap();
        assert_eq!(target, "/var/log/fail2ban.log");
    }

    #[test]
    fn get_logtarget_returns_syslog() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["get", "logtarget"], success("SYSLOG\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let target = client.get_logtarget().unwrap();
        assert_eq!(target, "SYSLOG");
    }

    // ===================================================================
    // get_dbfile
    // ===================================================================

    #[test]
    fn get_dbfile_returns_trimmed_output() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["get", "dbfile"],
            success("/var/lib/fail2ban/fail2ban.sqlite3\n"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let dbfile = client.get_dbfile().unwrap();
        assert_eq!(dbfile, "/var/lib/fail2ban/fail2ban.sqlite3");
    }

    #[test]
    fn get_dbfile_returns_none_when_disabled() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["get", "dbfile"], success("None\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let dbfile = client.get_dbfile().unwrap();
        assert_eq!(dbfile, "None");
    }

    // ===================================================================
    // get_dbpurgeage
    // ===================================================================

    #[test]
    fn get_dbpurgeage_returns_trimmed_output() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["get", "dbpurgeage"], success("86400\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let age = client.get_dbpurgeage().unwrap();
        assert_eq!(age, "86400");
    }

    #[test]
    fn get_dbpurgeage_returns_custom_value() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["get", "dbpurgeage"], success("604800\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let age = client.get_dbpurgeage().unwrap();
        assert_eq!(age, "604800");
    }

    // ===================================================================
    // str_to_seconds
    // ===================================================================

    #[test]
    fn str_to_seconds_parses_minutes() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--str2sec", "10m"], success("600\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let seconds = client.str_to_seconds("10m").unwrap();
        assert_eq!(seconds, "600");
    }

    #[test]
    fn str_to_seconds_parses_hours() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--str2sec", "1h"], success("3600\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let seconds = client.str_to_seconds("1h").unwrap();
        assert_eq!(seconds, "3600");
    }

    #[test]
    fn str_to_seconds_parses_days() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--str2sec", "7d"], success("604800\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let seconds = client.str_to_seconds("7d").unwrap();
        assert_eq!(seconds, "604800");
    }

    #[test]
    fn str_to_seconds_parses_permanent() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--str2sec", "-1"], success("-1\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let seconds = client.str_to_seconds("-1").unwrap();
        assert_eq!(seconds, "-1");
    }

    #[test]
    fn str_to_seconds_calls_correct_args() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--str2sec", "30m"], success("1800\n"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.str_to_seconds("30m").unwrap();

        let calls = fake.calls();
        assert_eq!(calls[0].1, vec!["--str2sec", "30m"]);
    }

    // ===================================================================
    // Error handling -- failed commands
    // ===================================================================

    #[test]
    fn ping_returns_error_on_nonzero_exit() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], failure("Failed to connect to server", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ping();
        assert!(result.is_err());
    }

    #[test]
    fn error_includes_exit_code_in_message() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], failure("Connection refused", 2));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ping();
        match result.unwrap_err() {
            crate::Error::CommandFailed(msg) => {
                assert!(
                    msg.contains("status 2"),
                    "expected exit code in error, got: {msg}"
                );
            }
            other => panic!("expected Error::CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn error_includes_stderr_in_message() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], failure("Failed to connect to server", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ping();
        match result.unwrap_err() {
            crate::Error::CommandFailed(msg) => {
                assert!(
                    msg.contains("Failed to connect"),
                    "expected stderr in error, got: {msg}"
                );
            }
            other => panic!("expected Error::CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn error_includes_binary_name_in_message() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], failure("some error", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ping();
        match result.unwrap_err() {
            crate::Error::CommandFailed(msg) => {
                assert!(
                    msg.contains("fail2ban-client"),
                    "expected binary name in error, got: {msg}"
                );
            }
            other => panic!("expected Error::CommandFailed, got {other:?}"),
        }
    }

    // ===================================================================
    // Error handling -- non-zero exit code with no stderr
    // ===================================================================

    #[test]
    fn error_handles_nonzero_without_stderr() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], failure_no_stderr(1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ping();
        match result.unwrap_err() {
            crate::Error::CommandFailed(msg) => {
                assert!(
                    msg.contains("status 1"),
                    "expected status code in error, got: {msg}"
                );
                assert!(
                    msg.contains("fail2ban-client"),
                    "expected binary name in error, got: {msg}"
                );
            }
            other => panic!("expected Error::CommandFailed, got {other:?}"),
        }
    }

    // ===================================================================
    // Error handling -- no exit code (signal / could not start)
    // ===================================================================

    #[test]
    fn error_handles_no_exit_code_with_stderr() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["ping"],
            failure_no_exit("Failed to connect to server"),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ping();
        match result.unwrap_err() {
            crate::Error::CommandFailed(msg) => {
                assert!(
                    msg.contains("Failed to connect"),
                    "expected stderr in error, got: {msg}"
                );
                assert!(
                    msg.contains("fail2ban-client"),
                    "expected binary name in error, got: {msg}"
                );
            }
            other => panic!("expected Error::CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn error_handles_no_exit_code_no_stderr() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], failure_no_exit(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        let result = client.ping();
        match result.unwrap_err() {
            crate::Error::CommandFailed(msg) => {
                assert!(
                    msg.contains("could not be started"),
                    "expected 'could not be started' in error, got: {msg}"
                );
            }
            other => panic!("expected Error::CommandFailed, got {other:?}"),
        }
    }

    // ===================================================================
    // Error handling -- multiple methods propagate errors consistently
    // ===================================================================

    #[test]
    fn version_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--version"], failure("unknown flag", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.version().is_err());
    }

    #[test]
    fn reload_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["reload"], failure("Cannot reload", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.reload().is_err());
    }

    #[test]
    fn reload_jail_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["reload", "nonexistent"],
            failure("Jail not found", 255),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.reload_jail("nonexistent").is_err());
    }

    #[test]
    fn status_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["status"], failure("server not running", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.status().is_err());
    }

    #[test]
    fn status_jail_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["status", "missing"], failure("Jail not found", 255));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.status_jail("missing").is_err());
    }

    #[test]
    fn ban_ip_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["set", "sshd", "banip", "1.2.3.4"],
            failure("Invalid command", 1),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.ban_ip("sshd", "1.2.3.4").is_err());
    }

    #[test]
    fn unban_ip_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["set", "sshd", "unbanip", "1.2.3.4"],
            failure("Invalid command", 1),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.unban_ip("sshd", "1.2.3.4").is_err());
    }

    #[test]
    fn banned_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["banned"], failure("server not running", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.banned().is_err());
    }

    #[test]
    fn banned_ip_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["banned", "1.2.3.4"], failure("error", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.banned_ip("1.2.3.4").is_err());
    }

    #[test]
    fn add_ignore_ip_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["set", "sshd", "addignoreip", "10.0.0.1"],
            failure("jail not found", 255),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.add_ignore_ip("sshd", "10.0.0.1").is_err());
    }

    #[test]
    fn remove_ignore_ip_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(
            BIN,
            &["set", "sshd", "delignoreip", "10.0.0.1"],
            failure("jail not found", 255),
        );

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.remove_ignore_ip("sshd", "10.0.0.1").is_err());
    }

    #[test]
    fn get_logtarget_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["get", "logtarget"], failure("error", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.get_logtarget().is_err());
    }

    #[test]
    fn get_dbfile_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["get", "dbfile"], failure("error", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.get_dbfile().is_err());
    }

    #[test]
    fn get_dbpurgeage_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["get", "dbpurgeage"], failure("error", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.get_dbpurgeage().is_err());
    }

    #[test]
    fn str_to_seconds_returns_error_on_nonzero() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["--str2sec", "invalid"], failure("invalid format", 1));

        let client = Fail2BanClient::with_binary(&fake, binary());
        assert!(client.str_to_seconds("invalid").is_err());
    }

    // ===================================================================
    // Call sequencing -- verify multiple calls are recorded in order
    // ===================================================================

    #[test]
    fn multiple_calls_are_recorded_in_order() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["ping"], success("pong"));
        fake.with_response(BIN, &["status"], success("ok"));
        fake.with_response(BIN, &["banned"], success("none"));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.ping().unwrap();
        client.status().unwrap();
        client.banned().unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1, vec!["ping"]);
        assert_eq!(calls[1].1, vec!["status"]);
        assert_eq!(calls[2].1, vec!["banned"]);
    }

    #[test]
    fn ban_then_unban_sequence() {
        let mut fake = FakeRunner::new();
        fake.with_response(BIN, &["set", "sshd", "banip", "1.2.3.4"], success("1"));
        fake.with_response(BIN, &["set", "sshd", "unbanip", "1.2.3.4"], success(""));

        let client = Fail2BanClient::with_binary(&fake, binary());
        client.ban_ip("sshd", "1.2.3.4").unwrap();
        client.unban_ip("sshd", "1.2.3.4").unwrap();

        let calls = fake.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, vec!["set", "sshd", "banip", "1.2.3.4"]);
        assert_eq!(calls[1].1, vec!["set", "sshd", "unbanip", "1.2.3.4"]);
    }
}
