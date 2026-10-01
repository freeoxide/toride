//! Spec-level execution policy knobs for security-sensitive embedders.
//!
//! Defaults preserve toride's historical semantics; embedders opt in per spec.

/// Shell metachars rejected from argv when [`ArgvPolicy::RejectShellMetachars`] is set.
pub const SHELL_METACHARS: &[&str] = &[
    "`", "$(", "${", "&&", "||", ";", "|", ">", "<", "&", "!", "\"", "'", "\n", "\r",
];

/// True when `value` contains any entry from [`SHELL_METACHARS`].
#[must_use]
pub fn contains_shell_metachars(value: &str) -> bool {
    SHELL_METACHARS.iter().any(|pat| value.contains(pat))
}

/// Which side wins when `env` and `env_remove` name the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EnvPrecedence {
    /// An explicit `env` entry beats `env_remove` on the same key (toride default).
    #[default]
    ExplicitWins,
    /// An `env_remove` entry beats an explicit `env` value on the same key.
    RemoveWins,
}

/// How the program is located before spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PathResolution {
    /// The runner passes the program through; bare names follow the
    /// parent-environment OS search (toride default).
    #[default]
    OsSearch,
    /// Bare names resolve against the child's composed `PATH`, falling back
    /// to the parent's when absent (error if neither): first executable
    /// match, empty entries skipped, cwd never searched; `.`/`..` refused.
    ChildEnvNoCwd,
}

/// Whether argv is validated before spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ArgvPolicy {
    /// No argv validation (toride default).
    #[default]
    Allow,
    /// Reject the spec when the program or any arg contains a [`SHELL_METACHARS`] entry.
    RejectShellMetachars,
}

/// Whether captured stdout plus stderr is capped, and at what size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OutputCap {
    /// Cap only when [`crate::spec::CommandSpec::output_limit`] opts in (toride default).
    #[default]
    OptIn,
    /// Always cap at this many bytes, overriding [`crate::spec::CommandSpec::output_limit`].
    Always(usize),
}

#[cfg(any(feature = "duct-runner", feature = "tokio-runner"))]
mod spawn_gate {
    use std::ffi::OsString;
    use std::path::{Component, Path, PathBuf};

    use super::{ArgvPolicy, EnvPrecedence, PathResolution, SHELL_METACHARS};
    use crate::error::{Error, Result};
    use crate::spec::CommandSpec;

    pub(crate) fn prepare_program(spec: &CommandSpec) -> Result<PathBuf> {
        validate_argv(spec)?;
        resolve_program(spec)
    }

    fn validate_argv(spec: &CommandSpec) -> Result<()> {
        if spec.argv_policy == ArgvPolicy::Allow {
            return Ok(());
        }
        if let Some(metachar) = first_metachar(&spec.program) {
            return Err(Error::ArgvRejected {
                program: spec.program.clone(),
                detail: format!("program contains shell metacharacter `{metachar}`"),
            });
        }
        for (index, arg) in spec.args.iter().enumerate() {
            if let Some(metachar) = first_metachar(arg) {
                return Err(Error::ArgvRejected {
                    program: spec.program.clone(),
                    detail: format!(
                        "argument at index {index} contains shell metacharacter `{metachar}`"
                    ),
                });
            }
        }
        Ok(())
    }

    fn resolve_program(spec: &CommandSpec) -> Result<PathBuf> {
        if spec.path_resolution == PathResolution::OsSearch {
            return Ok(PathBuf::from(&spec.program));
        }

        let path = Path::new(&spec.program);
        if path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(Error::ProgramRejected {
                program: spec.program.clone(),
                detail: "must not resolve relative to the working directory".to_owned(),
            });
        }
        if path.is_absolute() || spec.program.contains(std::path::MAIN_SEPARATOR) {
            return Ok(path.to_path_buf());
        }
        #[cfg(windows)]
        if spec.program.contains('/') {
            return Ok(path.to_path_buf());
        }

        resolve_bare_name(
            &spec.program,
            composed_child_path(spec),
            std::env::var_os("PATH"),
        )
    }

    fn resolve_bare_name(
        name: &str,
        composed: Option<OsString>,
        fallback: Option<OsString>,
    ) -> Result<PathBuf> {
        let Some(path_var) = composed.or(fallback) else {
            return Err(Error::ProgramRejected {
                program: name.to_owned(),
                detail: "PATH is not set; refusing to guess a search path for a bare name"
                    .to_owned(),
            });
        };

        first_path_match(&path_var, name).ok_or_else(|| Error::ProgramRejected {
            program: name.to_owned(),
            detail: "not found on PATH (first match; the working directory is never searched)"
                .to_owned(),
        })
    }

    fn first_metachar(value: &str) -> Option<&'static str> {
        SHELL_METACHARS
            .iter()
            .copied()
            .find(|pat| value.contains(pat))
    }

    fn composed_child_path(spec: &CommandSpec) -> Option<OsString> {
        let mut path = if spec.clear_env {
            None
        } else {
            std::env::var_os("PATH")
        };
        for (key, value) in &spec.env {
            if env_key_matches(key, "PATH") {
                path = Some(value.as_str().into());
            }
        }
        for key in &spec.env_remove {
            if env_key_matches(key, "PATH")
                && (spec.env_precedence == EnvPrecedence::RemoveWins
                    || !spec
                        .env
                        .iter()
                        .any(|(env_key, _)| env_key_matches(env_key, "PATH")))
            {
                path = None;
            }
        }
        path
    }

    fn first_path_match(path_var: &OsString, name: &str) -> Option<PathBuf> {
        for dir in std::env::split_paths(path_var) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
            #[cfg(windows)]
            {
                let exe = dir.join(format!("{name}.exe"));
                if is_executable_file(&exe) {
                    return Some(exe);
                }
            }
        }
        None
    }

    fn is_executable_file(path: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            std::fs::metadata(path).is_ok_and(|m| m.is_file())
        }
    }

    #[cfg(windows)]
    pub(crate) fn env_key_matches(a: &str, b: &str) -> bool {
        a.eq_ignore_ascii_case(b)
    }

    #[cfg(not(windows))]
    pub(crate) fn env_key_matches(a: &str, b: &str) -> bool {
        a == b
    }

    #[cfg(windows)]
    pub(crate) fn platform_env_preserved_for_clean_env() -> Vec<(String, String)> {
        ["SystemRoot", "SystemDrive", "WINDIR"]
            .into_iter()
            .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
            .collect()
    }

    #[cfg(not(windows))]
    pub(crate) fn platform_env_preserved_for_clean_env() -> Vec<(String, String)> {
        Vec::new()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn validate_argv_all_mode_accepts_metachars() {
            let spec = CommandSpec::new("echo").arg("a;b");
            assert!(validate_argv(&spec).is_ok());
        }

        #[test]
        fn validate_argv_rejects_metachar_arg() {
            let spec = CommandSpec::new("echo")
                .arg("a;b")
                .argv_policy(ArgvPolicy::RejectShellMetachars);
            match validate_argv(&spec) {
                Err(Error::ArgvRejected { program, detail }) => {
                    assert_eq!(program, "echo");
                    assert!(detail.contains("index 0"), "detail: {detail}");
                    assert!(!detail.contains("a;b"));
                }
                other => panic!("expected ArgvRejected, got {other:?}"),
            }
        }

        #[test]
        fn validate_argv_rejects_metachar_program() {
            let spec = CommandSpec::new("ec;ho").argv_policy(ArgvPolicy::RejectShellMetachars);
            match validate_argv(&spec) {
                Err(Error::ArgvRejected { program, detail }) => {
                    assert_eq!(program, "ec;ho");
                    assert!(detail.contains("program"));
                }
                other => panic!("expected ArgvRejected, got {other:?}"),
            }
        }

        #[test]
        fn validate_argv_rejects_first_offender_in_order() {
            let spec = CommandSpec::new("echo")
                .args(["ok", "x|y"])
                .argv_policy(ArgvPolicy::RejectShellMetachars);
            match validate_argv(&spec) {
                Err(Error::ArgvRejected { detail, .. }) => {
                    assert!(detail.contains("index 1"), "detail: {detail}");
                }
                other => panic!("expected ArgvRejected, got {other:?}"),
            }
        }

        #[test]
        fn resolve_program_os_search_passes_through_verbatim() {
            let spec = CommandSpec::new("./tool");
            assert_eq!(resolve_program(&spec).unwrap(), PathBuf::from("./tool"));
        }

        #[test]
        fn resolve_program_refuses_cwd_relative_spelling() {
            for program in ["./tool", "tool/../bin", "."] {
                let spec = CommandSpec::new(program).path_resolution(PathResolution::ChildEnvNoCwd);
                match resolve_program(&spec) {
                    Err(Error::ProgramRejected { program: p, detail }) => {
                        assert_eq!(p, program);
                        assert!(detail.contains("working directory"));
                    }
                    other => panic!("expected ProgramRejected, got {other:?}"),
                }
            }
        }

        #[test]
        fn resolve_program_absolute_passthrough() {
            let spec =
                CommandSpec::new("/usr/bin/env").path_resolution(PathResolution::ChildEnvNoCwd);
            assert_eq!(
                resolve_program(&spec).unwrap(),
                PathBuf::from("/usr/bin/env")
            );
        }

        #[test]
        fn resolve_program_separator_relative_passthrough() {
            let spec =
                CommandSpec::new("sub/dir/tool").path_resolution(PathResolution::ChildEnvNoCwd);
            assert_eq!(
                resolve_program(&spec).unwrap(),
                PathBuf::from("sub/dir/tool")
            );
        }

        #[test]
        fn resolve_program_child_path_wins_over_parent() {
            let spec = CommandSpec::new("sh")
                .env("PATH", "/nonexistent/toride-policy-probe")
                .path_resolution(PathResolution::ChildEnvNoCwd);
            match resolve_program(&spec) {
                Err(Error::ProgramRejected { program, detail }) => {
                    assert_eq!(program, "sh");
                    assert!(detail.contains("not found on PATH"), "detail: {detail}");
                }
                other => panic!("expected ProgramRejected, got {other:?}"),
            }
        }

        #[test]
        fn resolve_bare_name_not_found_detail_does_not_misname_the_searched_path() {
            let missing = "definitely_not_a_real_binary_xyz_123";
            let searched = OsString::from("/nonexistent/toride-policy-probe");
            match resolve_bare_name(missing, None, Some(searched)) {
                Err(Error::ProgramRejected { detail, .. }) => {
                    assert!(detail.contains("not found on PATH"), "detail: {detail}");
                    assert!(
                        !detail.contains("child"),
                        "fallback search must not be misnamed as the child PATH: {detail}"
                    );
                }
                other => panic!("expected ProgramRejected, got {other:?}"),
            }
        }

        #[test]
        fn resolve_program_skips_empty_path_entries() {
            let spec = CommandSpec::new("sh")
                .env("PATH", ":")
                .path_resolution(PathResolution::ChildEnvNoCwd);
            assert!(matches!(
                resolve_program(&spec),
                Err(Error::ProgramRejected { .. })
            ));
        }

        #[test]
        fn resolve_bare_name_errors_when_no_path_anywhere() {
            match resolve_bare_name("sh", None, None) {
                Err(Error::ProgramRejected { program, detail }) => {
                    assert_eq!(program, "sh");
                    assert!(detail.contains("PATH is not set"), "detail: {detail}");
                }
                other => panic!("expected ProgramRejected, got {other:?}"),
            }
        }

        #[test]
        fn resolve_bare_name_falls_back_when_composed_path_absent() {
            let dir = tempfile::tempdir().unwrap();
            let found = resolve_bare_name(
                "sh",
                None,
                Some(dir.path().to_string_lossy().into_owned().into()),
            );
            assert!(found.is_err(), "empty fallback PATH must not resolve sh");
        }

        #[cfg(unix)]
        #[test]
        fn resolve_program_finds_first_executable_on_child_path() {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("toride_policy_probe");
            std::fs::write(&path, "#!/bin/sh\n").unwrap();
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();

            let later = tempfile::tempdir().unwrap();
            let joined = format!("{}:{}", dir.path().display(), later.path().display());
            let spec = CommandSpec::new("toride_policy_probe")
                .env("PATH", joined)
                .path_resolution(PathResolution::ChildEnvNoCwd);
            assert_eq!(resolve_program(&spec).unwrap(), path);
        }

        #[cfg(unix)]
        #[test]
        fn resolve_program_requires_execute_bit() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("toride_policy_noexec");
            std::fs::write(&path, "not executable").unwrap();

            let spec = CommandSpec::new("toride_policy_noexec")
                .env("PATH", dir.path().to_string_lossy().into_owned())
                .path_resolution(PathResolution::ChildEnvNoCwd);
            assert!(matches!(
                resolve_program(&spec),
                Err(Error::ProgramRejected { .. })
            ));
        }

        #[cfg(unix)]
        #[test]
        fn resolve_program_non_executable_file_is_not_a_match() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("toride_policy_plain"), "data").unwrap();

            let spec = CommandSpec::new("toride_policy_plain")
                .env("PATH", dir.path().to_string_lossy().into_owned())
                .path_resolution(PathResolution::ChildEnvNoCwd);
            assert!(matches!(
                resolve_program(&spec),
                Err(Error::ProgramRejected { .. })
            ));
        }

        #[cfg(unix)]
        #[test]
        fn resolve_program_env_remove_wins_over_env_path_under_remove_wins() {
            let dir = tempfile::tempdir().unwrap();
            let spec = CommandSpec::new("sh")
                .env("PATH", dir.path().to_string_lossy().into_owned())
                .env_remove("PATH")
                .env_precedence(EnvPrecedence::RemoveWins)
                .path_resolution(PathResolution::ChildEnvNoCwd);
            let resolved = resolve_program(&spec).unwrap();
            let parent = std::env::var_os("PATH").unwrap_or_default();
            let found_on_parent = std::env::split_paths(&parent).any(|d| d.join("sh") == resolved);
            assert!(
                found_on_parent,
                "removed child PATH must fall back to the parent PATH: {resolved:?}"
            );
        }

        #[cfg(unix)]
        #[test]
        fn resolve_program_clear_env_falls_back_to_parent_path() {
            let spec = CommandSpec::new("sh")
                .clear_env(true)
                .path_resolution(PathResolution::ChildEnvNoCwd);
            let resolved = resolve_program(&spec).unwrap();
            let parent = std::env::var_os("PATH").unwrap_or_default();
            let found_on_parent = std::env::split_paths(&parent).any(|d| d.join("sh") == resolved);
            assert!(found_on_parent, "unexpected resolution: {resolved:?}");
        }
    }
}

#[cfg(any(feature = "duct-runner", feature = "tokio-runner"))]
pub(crate) use spawn_gate::{
    env_key_matches, platform_env_preserved_for_clean_env, prepare_program,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_shell_metachars_detects_each_class() {
        for value in [
            "a;b", "a|b", "a>b", "a<b", "a&b", "a!b", "a\"b", "a'b", "a\nb", "a\rb", "a`b",
            "a$(b)", "a${b}", "a&&b", "a||b",
        ] {
            assert!(contains_shell_metachars(value), "{value} should match");
        }
    }

    #[test]
    fn contains_shell_metachars_passes_plain_argv() {
        for value in ["brew", "install", "--cask", "firefox", "foo:bar", "a b"] {
            assert!(!contains_shell_metachars(value), "{value} should pass");
        }
    }
}
