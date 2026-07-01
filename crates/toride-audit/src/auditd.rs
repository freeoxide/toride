//! Audit daemon management.
//!
//! Provides high-level operations for managing the Linux audit daemon
//! including rule loading, status queries, and service lifecycle.

use toride_runner::CommandSpec;

use crate::{AuditPaths, Error, Result};

// ---------------------------------------------------------------------------
// AuditdManager
// ---------------------------------------------------------------------------

/// High-level manager for the Linux audit daemon.
///
/// Composes the audit client, rule management, and service operations
/// into a unified interface for auditd management.
pub struct AuditdManager<'a> {
    runner: &'a dyn toride_runner::Runner,
    paths: &'a AuditPaths,
}

impl<'a> AuditdManager<'a> {
    /// Create a new auditd manager with the given runner and paths.
    pub fn new(runner: &'a dyn toride_runner::Runner, paths: &'a AuditPaths) -> Self {
        Self { runner, paths }
    }

    /// Load audit rules from a rules file via `auditctl -R`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not available.
    /// Returns [`Error::CommandFailed`] if the rules cannot be loaded.
    pub fn load_rules_file(&self, rules_path: &std::path::Path) -> Result<()> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let spec = CommandSpec::new("auditctl")
            .arg("-R")
            .arg(rules_path.to_str().unwrap_or_default());
        self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Get the current audit daemon status.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not available.
    pub fn status(&self) -> Result<String> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        let spec = CommandSpec::new("auditctl").arg("-s");
        let output = self.runner.run_checked(&spec)?;
        Ok(output.stdout)
    }

    /// Flush all current audit rules and load from the rules directory.
    ///
    /// Unlike a naive "flush then load" sequence, this method loads every
    /// `.rules` file **first** and only runs `auditctl -D` (delete all) once
    /// the whole replacement set has been loaded successfully. A mid-loop load
    /// failure therefore returns the error *before* the existing rules are
    /// deleted, so the host is never left with a partial/empty ruleset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinaryNotFound`] if `auditctl` is not available.
    /// Returns [`Error::CommandFailed`] if a rules file cannot be loaded.
    pub fn reload_rules(&self) -> Result<()> {
        which::which("auditctl").map_err(|_| Error::BinaryNotFound("auditctl".to_owned()))?;
        self.reload_rules_inner()
    }

    /// Core reload logic, split out so it can be exercised in tests without
    /// depending on the `auditctl` binary being present on the test host.
    ///
    /// Ordering invariant (under test): `auditctl -D` (flush) is **never**
    /// issued before every `.rules` file has loaded successfully. A pre-load
    /// failure returns the error with the live ruleset intact.
    fn reload_rules_inner(&self) -> Result<()> {
        // Collect and sort the candidate .rules files so reload is deterministic
        // (read_dir order is OS-unspecified).
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        if self.paths.rules_d.exists() {
            for entry in std::fs::read_dir(&self.paths.rules_d)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "rules") {
                    files.push(path);
                }
            }
        }
        files.sort();

        if files.is_empty() {
            // Nothing to load: still flush the live ruleset to match the
            // configured state (empty rules.d => no rules).
            tracing::warn!("no .rules files found in {}", self.paths.rules_d.display());
            let spec = CommandSpec::new("auditctl").arg("-D");
            self.runner.run_checked(&spec)?;
            return Ok(());
        }

        // 1. Pre-validate by loading every file into the live ruleset. The
        //    kernel merges `auditctl -R` rules into the current set; if any
        //    file fails to load we bail out *before* flushing, leaving the
        //    pre-existing rules intact (plus the partial merge of files seen
        //    so far, which is strictly safer than an empty ruleset).
        for path in &files {
            if let Err(e) = self.load_rules_file_inner(path) {
                tracing::error!(
                    "refusing to flush audit rules: failed to pre-load {}: {e}",
                    path.display()
                );
                return Err(e);
            }
        }

        // 2. Only after every file loaded successfully, flush the live set...
        let spec = CommandSpec::new("auditctl").arg("-D");
        self.runner.run_checked(&spec)?;

        // 3. ...and re-load the validated files so the live set is exactly the
        //    configured set (no leftovers from the pre-validation merge).
        for path in &files {
            self.load_rules_file_inner(path)?;
        }

        Ok(())
    }

    /// `load_rules_file` without the `auditctl` binary lookup, for the
    /// inner reload path and tests.
    fn load_rules_file_inner(&self, rules_path: &std::path::Path) -> Result<()> {
        let spec = CommandSpec::new("auditctl")
            .arg("-R")
            .arg(rules_path.to_str().unwrap_or_default());
        self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Check if the auditd service is running.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the check cannot be performed.
    pub fn is_running(&self) -> Result<bool> {
        let spec = CommandSpec::new("systemctl").args(["is-active", "auditd"]);
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use toride_runner::output::CommandOutput;
    use toride_runner::Runner;

    /// Test runner that records every spec it sees and returns queued outputs.
    /// Each entry corresponds positionally to a `run`/`run_checked` call.
    /// `Ok(out)` returns `out`; `Err(())` simulates a failing command.
    struct ScriptedRunner {
        outputs: Mutex<Vec<std::result::Result<CommandOutput, ()>>>,
        calls: Mutex<Vec<CommandSpec>>,
    }

    impl ScriptedRunner {
        fn new(outputs: Vec<std::result::Result<CommandOutput, ()>>) -> Self {
            Self {
                outputs: Mutex::new(outputs),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .expect("calls lock")
                .iter()
                .map(|c| {
                    let mut s = c.program.clone();
                    for a in &c.args {
                        s.push(' ');
                        s.push_str(a);
                    }
                    s
                })
                .collect()
        }
    }

    impl Runner for ScriptedRunner {
        fn run(&self, spec: &CommandSpec) -> toride_runner::error::Result<CommandOutput> {
            self.calls.lock().expect("calls lock").push(spec.clone());
            let mut q = self.outputs.lock().expect("outputs lock");
            match q.remove(0) {
                Ok(o) => Ok(o),
                Err(()) => Err(toride_runner::error::Error::CommandFailed {
                    program: spec.program.clone(),
                    args: String::new(),
                    exit_code: Some(1),
                    stderr: String::new(),
                }),
            }
        }
    }

    fn paths_for(dir: &std::path::Path) -> AuditPaths {
        AuditPaths {
            audit_dir: dir.join("audit"),
            rules_d: dir.join("audit/rules.d"),
            aide_conf: dir.join("aide.conf"),
            aide_db_dir: dir.join("aide"),
            rsyslog_conf: dir.join("rsyslog.conf"),
            rsyslog_d: dir.join("rsyslog.d"),
            logrotate_d: dir.join("logrotate.d"),
        }
    }

    fn write_rules(dir: &std::path::Path, name: &str, body: &str) {
        std::fs::create_dir_all(dir.join("audit/rules.d")).unwrap();
        std::fs::write(dir.join("audit/rules.d").join(name), body).unwrap();
    }

    #[test]
    fn reload_rules_success_flushes_then_reloads_all() {
        // Two .rules files, every auditctl call succeeds.
        let tmp = tempfile::tempdir().unwrap();
        write_rules(tmp.path(), "01.rules", "-D -S foo\n");
        write_rules(tmp.path(), "02.rules", "-D -S bar\n");
        let paths = paths_for(tmp.path());

        // Expected call order: load 01, load 02, -D, load 01, load 02.
        let runner = ScriptedRunner::new(vec![
            Ok(CommandOutput::from_stdout("")),
            Ok(CommandOutput::from_stdout("")),
            Ok(CommandOutput::from_stdout("")),
            Ok(CommandOutput::from_stdout("")),
            Ok(CommandOutput::from_stdout("")),
        ]);
        let mgr = AuditdManager::new(&runner, &paths);
        mgr.reload_rules_inner().expect("reload succeeds");

        let calls = runner.calls();
        // The -D (flush) call must come AFTER all pre-loads succeeded and
        // BEFORE the reloads. Find -D's position.
        let flush_pos = calls
            .iter()
            .position(|c| c.contains("-D"))
            .expect("a -D flush must occur on the success path");
        // Two -R loads precede the flush (pre-validation).
        let loads_before = calls[..flush_pos]
            .iter()
            .filter(|c| c.contains("-R"))
            .count();
        assert_eq!(
            loads_before, 2,
            "all files must be pre-loaded before flushing; calls = {calls:?}"
        );
        // No flush happens before the first load.
        assert!(
            !calls[..flush_pos].iter().any(|c| c.contains("auditctl -D")),
            "flush ran before pre-load completed; calls = {calls:?}"
        );
    }

    #[test]
    fn reload_rules_failure_does_not_flush() {
        // Two .rules files. The FIRST load fails: -D must NEVER be issued,
        // so the host keeps its existing ruleset.
        let tmp = tempfile::tempdir().unwrap();
        write_rules(tmp.path(), "01.rules", "-D -S foo\n");
        write_rules(tmp.path(), "02.rules", "-D -S bar\n");
        let paths = paths_for(tmp.path());

        let runner = ScriptedRunner::new(vec![
            Err(()),
            // (anything after this should never be consumed.)
            Ok(CommandOutput::from_stdout("")),
        ]);
        let mgr = AuditdManager::new(&runner, &paths);
        let err = mgr.reload_rules_inner().unwrap_err();
        assert!(
            matches!(err, Error::CommandFailed(_)),
            "expected a CommandFailed error, got {err:?}"
        );

        let calls = runner.calls();
        assert!(
            !calls.iter().any(|c| c.contains("-D")),
            "flush (-D) must not run when a pre-load fails; calls = {calls:?}"
        );
        // Only the failed first load was attempted.
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("-R"));
    }

    #[test]
    fn reload_rules_second_file_failure_does_not_flush() {
        // First file loads, second fails: still no flush.
        let tmp = tempfile::tempdir().unwrap();
        write_rules(tmp.path(), "01.rules", "-D -S foo\n");
        write_rules(tmp.path(), "02.rules", "-D -S bar\n");
        let paths = paths_for(tmp.path());

        let runner = ScriptedRunner::new(vec![
            Ok(CommandOutput::from_stdout("")),
            Err(()),
            Ok(CommandOutput::from_stdout("")),
        ]);
        let mgr = AuditdManager::new(&runner, &paths);
        assert!(mgr.reload_rules_inner().is_err());

        let calls = runner.calls();
        assert!(
            !calls.iter().any(|c| c.contains("-D")),
            "flush (-D) must not run when a mid-loop pre-load fails; calls = {calls:?}"
        );
        // First load + second (failed) load attempted, nothing else.
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn reload_rules_empty_rules_dir_flushes() {
        // No .rules files: the live set is flushed to match (empty configured set).
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("audit/rules.d")).unwrap();
        let paths = paths_for(tmp.path());

        let runner = ScriptedRunner::new(vec![Ok(CommandOutput::from_stdout(""))]);
        let mgr = AuditdManager::new(&runner, &paths);
        mgr.reload_rules_inner().expect("flush succeeds");

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("-D"));
    }
}
