use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;

type CallLog = Arc<Mutex<Vec<(String, Vec<String>)>>>;

struct RecordingRunner {
    calls: CallLog,
    dry_run: bool,
}

impl RecordingRunner {
    fn new() -> (Self, CallLog) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                calls: Arc::clone(&calls),
                dry_run: false,
            },
            calls,
        )
    }
}

impl command::Runner for RecordingRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<command::CommandOutput> {
        self.calls.lock().expect("mutex not poisoned").push((
            program.to_owned(),
            args.iter().map(|a| (*a).to_owned()).collect(),
        ));
        Ok(command::CommandOutput::new(
            String::new(),
            String::new(),
            Some(0),
        ))
    }

    fn run_with_timeout(
        &self,
        program: &str,
        args: &[&str],
        _timeout: Duration,
    ) -> Result<command::CommandOutput> {
        self.run(program, args)
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }
}

fn temp_paths() -> (tempfile::TempDir, SystemPaths) {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("jail.d")).expect("jail.d");
    std::fs::create_dir_all(dir.path().join("filter.d")).expect("filter.d");
    std::fs::create_dir_all(dir.path().join("action.d")).expect("action.d");
    let paths = SystemPaths::with_config_dir(dir.path().to_path_buf()).expect("paths");
    (dir, paths)
}

#[cfg(feature = "client")]
#[test]
fn dry_run_facade_verbs_never_invoke_the_runner() {
    let (_dir, paths) = temp_paths();
    let (runner, calls) = RecordingRunner::new();
    let f2b = Fail2Ban::with_runner_and_paths(Box::new(runner), paths).with_dry_run(true);

    f2b.test_config().expect("dry-run test_config succeeds");
    f2b.reload().expect("dry-run reload succeeds");
    f2b.reload_jail("sshd")
        .expect("dry-run reload_jail succeeds");
    f2b.ban_ip("sshd", "203.0.113.9")
        .expect("dry-run ban_ip succeeds");
    f2b.unban_ip("sshd", "203.0.113.9")
        .expect("dry-run unban_ip succeeds");

    assert!(
        calls.lock().expect("mutex not poisoned").is_empty(),
        "dry-run facade verbs must not spawn any command"
    );
}

#[cfg(feature = "client")]
#[test]
fn dry_run_flag_propagates_to_the_runner() {
    use super::command::Runner as _;

    let (_dir, paths) = temp_paths();
    let mut runner = command::DuctRunner::new();
    runner.set_dry_run(false);
    let f2b = Fail2Ban::with_runner_and_paths(Box::new(runner), paths).with_dry_run(true);
    assert!(f2b.dry_run());
}

#[cfg(feature = "client")]
#[test]
fn facade_rejects_option_like_operands_without_spawning() {
    let (_dir, paths) = temp_paths();
    let (runner, calls) = RecordingRunner::new();
    let f2b = Fail2Ban::with_runner_and_paths(Box::new(runner), paths);

    assert!(matches!(f2b.reload_jail("-h"), Err(Error::Validation(_))));
    assert!(matches!(
        f2b.ban_ip("-h", "1.2.3.4"),
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        f2b.unban_ip("my jail", "1.2.3.4"),
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        f2b.ban_ip("sshd", "not-an-ip"),
        Err(Error::Validation(_))
    ));

    assert!(
        calls.lock().expect("mutex not poisoned").is_empty(),
        "a rejected operand must never spawn fail2ban-client"
    );
}

#[cfg(feature = "client")]
#[test]
fn dry_run_facade_still_rejects_option_like_operands() {
    let (_dir, paths) = temp_paths();
    let (runner, calls) = RecordingRunner::new();
    let f2b = Fail2Ban::with_runner_and_paths(Box::new(runner), paths).with_dry_run(true);

    assert!(matches!(
        f2b.ban_ip("-h", "1.2.3.4"),
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        f2b.reload_jail("my jail"),
        Err(Error::Validation(_))
    ));

    assert!(
        calls.lock().expect("mutex not poisoned").is_empty(),
        "dry-run skips execution, not operand validation"
    );
}

#[cfg(all(feature = "jail-lifecycle", feature = "client"))]
#[test]
fn remove_jail_rejects_option_like_names() {
    let (_dir, paths) = temp_paths();
    let (runner, _calls) = RecordingRunner::new();
    let f2b = Fail2Ban::with_runner_and_paths(Box::new(runner), paths);

    assert!(matches!(f2b.remove_jail("-h"), Err(Error::Validation(_))));
}

#[cfg(all(feature = "jail-lifecycle", feature = "client"))]
fn inline_filter_jail() -> spec::JailSpec {
    spec::JailSpec::builder()
        .name("myapp".parse().expect("valid jail name"))
        .filter(
            spec::FilterSpec::builder()
                .name("myapp-auth".parse().expect("valid filter name"))
                .failregex(vec![
                    spec::RegexLine::new(r"^.*Authentication failed.*from <HOST>.*$")
                        .expect("valid failregex"),
                ])
                .build(),
        )
        .actions(vec![
            spec::ActionSpec::builder()
                .name("myhook".parse().expect("valid action name"))
                .kind(spec::ActionKind::Custom)
                .actionban(Some("/usr/local/bin/f2b-hook ban <ip>".to_owned()))
                .actionunban(Some("/usr/local/bin/f2b-hook unban <ip>".to_owned()))
                .build(),
        ])
        .log_paths(vec!["/var/log/auth.log".parse().expect("path")])
        .bantime("10m".parse().expect("duration"))
        .findtime("5m".parse().expect("duration"))
        .maxretry(5)
        .build()
}

#[cfg(all(feature = "jail-lifecycle", feature = "client"))]
#[test]
fn ensure_jail_writes_inline_filter_and_custom_action_under_namespaced_names() {
    let (dir, paths) = temp_paths();
    let (runner, _calls) = RecordingRunner::new();
    let f2b = Fail2Ban::with_runner_and_paths(Box::new(runner), paths);

    let report = f2b.ensure_jail(inline_filter_jail()).expect("apply works");

    let ns = ini::DEFAULT_NAMESPACE;
    let jail_file = dir.path().join(format!("jail.d/{ns}-myapp.local"));
    let filter_file = dir.path().join(format!("filter.d/{ns}-myapp-auth.local"));
    let action_file = dir.path().join(format!("action.d/{ns}-myhook.local"));

    for path in [&jail_file, &filter_file, &action_file] {
        assert!(
            report
                .files_written
                .iter()
                .any(|w| w == &path.display().to_string()),
            "report must list {}: got {:?}",
            path.display(),
            report.files_written
        );
    }

    let jail_content = std::fs::read_to_string(&jail_file).expect("jail written");
    assert!(
        jail_content.contains(&format!("filter = {ns}-myapp-auth")),
        "jail must reference the namespaced filter file: {jail_content}"
    );
    assert!(
        jail_content.contains(&format!("action = {ns}-myhook")),
        "jail must reference the namespaced action file: {jail_content}"
    );

    let filter_content = std::fs::read_to_string(&filter_file).expect("filter written");
    assert!(
        filter_content.contains("[Definition]"),
        "filter must use the [Definition] section fail2ban reads: {filter_content}"
    );
    assert!(filter_content.contains("failregex = "));
    assert!(filter_content.starts_with(render::managed_header().trim_end()));

    let action_content = std::fs::read_to_string(&action_file).expect("action written");
    assert!(
        action_content.contains("[Definition]"),
        "action must use the [Definition] section fail2ban reads: {action_content}"
    );
    assert!(action_content.contains("actionban = "));
}

#[cfg(all(feature = "jail-lifecycle", feature = "client"))]
#[test]
fn ensure_jail_references_stock_filter_and_action_by_bare_name() {
    let (dir, paths) = temp_paths();
    let (runner, _calls) = RecordingRunner::new();
    let f2b = Fail2Ban::with_runner_and_paths(Box::new(runner), paths);

    let spec = spec::JailSpec::builder()
        .name("stockapp".parse().expect("valid jail name"))
        .filter(spec::FilterSpec::named("sshd").expect("named filter"))
        .actions(vec![
            spec::ActionSpec::stock("nftables-multiport").expect("stock action"),
        ])
        .log_paths(vec!["/var/log/auth.log".parse().expect("path")])
        .bantime("10m".parse().expect("duration"))
        .findtime("5m".parse().expect("duration"))
        .build();

    let report = f2b.ensure_jail(spec).expect("apply works");

    let ns = ini::DEFAULT_NAMESPACE;
    assert_eq!(
        report.files_written.len(),
        1,
        "only the jail file is written"
    );
    let jail_file = dir.path().join(format!("jail.d/{ns}-stockapp.local"));
    let jail_content = std::fs::read_to_string(&jail_file).expect("jail written");
    assert!(
        jail_content.contains("filter = sshd\n"),
        "stock filter referenced bare: {jail_content}"
    );
    assert!(
        jail_content.contains("action = nftables-multiport\n"),
        "stock action referenced bare: {jail_content}"
    );
    assert!(
        !dir.path()
            .join(format!("filter.d/{ns}-sshd.local"))
            .exists()
    );
}
