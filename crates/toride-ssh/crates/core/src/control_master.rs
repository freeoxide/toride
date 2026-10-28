//! Canonical `ControlMaster` socket discovery and file-name parsing.
//!
//! Every subsystem that enumerates `ControlMaster` sockets (the agent's
//! session list, the forward crate's session list) funnels through
//! [`collect_control_candidates`] and [`ControlName::parse`], so the
//! candidate heuristics and the socket-name grammar live in one place
//! instead of one copy per consumer.

use std::path::{Path, PathBuf};

/// Upper bound on the size of a regular file treated as a candidate socket.
const MAX_PLAIN_FILE_LEN: u64 = 1024;

/// A file that resembles a `ControlMaster` socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCandidate {
    /// Path of the candidate file.
    pub path: PathBuf,
    /// What the file was matched as.
    pub kind: ControlCandidateKind,
}

/// How a [`ControlCandidate`] was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCandidateKind {
    /// A Unix domain socket.
    Socket,
    /// A regular file below 1 KiB whose name contains no `.`, kept for
    /// `ControlPath` patterns and platforms where sockets are absent.
    PlainFile,
}

/// Collect `ControlMaster` socket candidates whose file name starts with any
/// of `prefixes`.
///
/// Delegates to [`collect_control_candidates_with`] with a prefix test; see
/// that function for the file-kind rules.
///
/// # Errors
///
/// Returns the [`std::io::Error`] from reading `dir` unless the directory
/// is missing, which yields an empty vec.
pub fn collect_control_candidates(
    dir: &Path,
    prefixes: &[&str],
    include_plain_files: bool,
) -> std::io::Result<Vec<ControlCandidate>> {
    collect_control_candidates_with(
        dir,
        |name| prefixes.iter().any(|prefix| name.starts_with(prefix)),
        include_plain_files,
    )
}

/// Collect `ControlMaster` socket candidates whose file name satisfies
/// `name_matches`.
///
/// A candidate is a directory entry whose file name passes `name_matches`
/// and that is either a Unix domain socket or, when `include_plain_files` is
/// set, a regular file below 1 KiB whose name contains no `.`. Sockets are
/// always accepted regardless of `include_plain_files`. A missing directory
/// yields an empty vec; any other read error is returned to the caller so
/// each consumer keeps its own error policy.
///
/// # Errors
///
/// Returns the [`std::io::Error`] from reading `dir` unless the directory
/// is missing, which yields an empty vec.
pub fn collect_control_candidates_with<F>(
    dir: &Path,
    name_matches: F,
    include_plain_files: bool,
) -> std::io::Result<Vec<ControlCandidate>>
where
    F: Fn(&str) -> bool,
{
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name_matches(name) {
            continue;
        }
        if let Some(kind) = candidate_kind(&path, include_plain_files) {
            out.push(ControlCandidate { path, kind });
        }
    }
    Ok(out)
}

/// Classify `path` as a candidate, or `None` when it cannot be one.
fn candidate_kind(path: &Path, include_plain_files: bool) -> Option<ControlCandidateKind> {
    let meta = std::fs::metadata(path).ok()?;
    let file_type = meta.file_type();

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt as _;
        if file_type.is_socket() {
            return Some(ControlCandidateKind::Socket);
        }
    }

    if include_plain_files && file_type.is_file() && meta.len() < MAX_PLAIN_FILE_LEN {
        let dotless = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| !n.contains('.'));
        return dotless.then_some(ControlCandidateKind::PlainFile);
    }
    None
}

/// Fields parsed from a `ControlMaster` socket file name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlName {
    /// User portion before the `@`, when the name carries one.
    pub user: Option<String>,
    /// Host portion: prefix, port, and random suffix stripped, IPv6 brackets
    /// removed.
    pub host: String,
    /// Trailing `-<pid>` when the text after the last dash parses as a
    /// non-zero pid.
    pub pid: Option<u32>,
}

/// Prefixes OpenSSH `ControlPath` patterns commonly produce.
const NAME_PREFIXES: &[&str] = &["cm-", "control-", "mux-", "ctrl-", "ssh-"];

impl ControlName {
    /// Parse a `ControlMaster` socket file name such as `cm-root@web01:22`,
    /// `ssh-abc123def-48291`, or `mux-user@[2001:db8::1]:22`.
    ///
    /// One of the [`NAME_PREFIXES`] is stripped when present. Parsing is
    /// best-effort: unrecognized shapes keep the whole remainder in
    /// [`host`](Self::host) so unknown `ControlPath` patterns stay visible
    /// instead of collapsing to an empty string.
    #[must_use]
    pub fn parse(name: &str) -> Self {
        let rest = NAME_PREFIXES
            .iter()
            .find_map(|prefix| name.strip_prefix(prefix))
            .unwrap_or(name);

        let (user, host) = match rest.split_once('@') {
            Some((user, after_at)) => (Some(user), host_after_at(after_at)),
            None => (None, host_without_user(rest)),
        };

        Self {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            pid: pid_from_tail(name),
        }
    }
}

/// Host portion of a name without `user@`: cut at the first `:` (a port or a
/// bare `host:port` tail), keep everything else.
fn host_without_user(rest: &str) -> &str {
    match rest.split_once(':') {
        Some((host, _)) => host,
        None => rest,
    }
}

/// Host portion of the text after `user@`.
///
/// Bracketed IPv6 yields the address inside the brackets; a bare IPv6 shape
/// (three or more colons including `::` and a numeric tail) yields the
/// address before the port; otherwise a single `:` cuts the port and a `-`
/// cuts a trailing random suffix, in that order.
fn host_after_at(after_at: &str) -> &str {
    if after_at.starts_with('[')
        && let Some(bracket_end) = after_at.find(']')
    {
        return &after_at[1..bracket_end];
    }

    let colon_count = after_at.matches(':').count();
    if colon_count >= 2 {
        return split_bare_ipv6_host_port(after_at).unwrap_or(after_at);
    }
    if let Some(colon) = after_at.find(':') {
        return &after_at[..colon];
    }
    if let Some(dash) = after_at.find('-') {
        return &after_at[..dash];
    }
    after_at
}

/// Split `host:port` for a bare (unbracketed) IPv6 address, or `None` when
/// the text is not that shape.
fn split_bare_ipv6_host_port(s: &str) -> Option<&str> {
    if s.matches(':').count() < 3 || !s.contains("::") {
        return None;
    }
    let last_colon = s.rfind(':')?;
    let port_part = &s[last_colon + 1..];
    if port_part.is_empty() || !port_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let host_part = &s[..last_colon];
    (!host_part.is_empty()).then_some(host_part)
}

/// Trailing `-<pid>` of the full file name, when it parses as a non-zero
/// `u32`.
fn pid_from_tail(name: &str) -> Option<u32> {
    let (_prefix, pid_str) = name.rsplit_once('-')?;
    let pid: u32 = pid_str.parse().ok()?;
    (pid > 0).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn make_socket_file(path: &std::path::Path) {
        let listener = std::os::unix::net::UnixListener::bind(path).expect("bind test socket");
        std::mem::forget(listener);
    }

    #[test]
    fn parse_strips_prefix_and_port() {
        assert_eq!(
            ControlName::parse("cm-deploy@web01.example.com:22"),
            ControlName {
                user: Some("deploy".into()),
                host: "web01.example.com".into(),
                pid: None,
            }
        );
        assert_eq!(ControlName::parse("control-root@db:5432").host, "db");
        assert_eq!(ControlName::parse("mux-user@bastion:22").host, "bastion");
        assert_eq!(ControlName::parse("ctrl-user@jump:22").host, "jump");
    }

    #[test]
    fn parse_keeps_hash_and_suffix_without_user() {
        let parts = ControlName::parse("ssh-abc123def456-12345");
        assert_eq!(parts.user, None);
        assert_eq!(parts.host, "abc123def456-12345");
        assert_eq!(parts.pid, Some(12345));
    }

    #[test]
    fn parse_no_at_sign_passes_through() {
        assert_eq!(
            ControlName::parse("some-random-name").host,
            "some-random-name"
        );
    }

    #[test]
    fn parse_only_prefix_yields_empty_host() {
        assert_eq!(ControlName::parse("cm-").host, "");
    }

    #[test]
    fn parse_user_without_port() {
        assert_eq!(ControlName::parse("cm-user@host").host, "host");
    }

    #[test]
    fn parse_ipv6_forms() {
        assert_eq!(ControlName::parse("cm-user@[::1]:22").host, "::1");
        assert_eq!(
            ControlName::parse("cm-user@[2001:db8::1]:22").host,
            "2001:db8::1"
        );
        assert_eq!(ControlName::parse("cm-user@[::1]").host, "::1");
        assert_eq!(
            ControlName::parse("cm-user@[fe80::250:56ff:feb3:6477]:22").host,
            "fe80::250:56ff:feb3:6477"
        );
        assert_eq!(ControlName::parse("cm-user@::1:22").host, "::1");
        assert_eq!(ControlName::parse("cm-user@fe80::1:22").host, "fe80::1");
        assert_eq!(ControlName::parse("mux-user@::1:65535").host, "::1");
        assert_eq!(ControlName::parse("cm-user@::1").host, "::1");
    }

    #[test]
    fn parse_separators_and_suffixes() {
        assert_eq!(
            ControlName::parse("cm-user_name@host_name:22").host,
            "host_name"
        );
        assert_eq!(ControlName::parse("cm-user@my-host:22").host, "my-host");
        assert_eq!(
            ControlName::parse("cm-user@192.168.1.1:22").host,
            "192.168.1.1"
        );
        assert_eq!(
            ControlName::parse("ssh-deploy@web01:22-mUXnBz"),
            ControlName {
                user: Some("deploy".into()),
                host: "web01".into(),
                pid: None,
            }
        );
        assert_eq!(ControlName::parse("ssh-deploy@web01-mUXnBz").host, "web01");
    }

    #[test]
    fn parse_user_and_host_round_trip() {
        let parts = ControlName::parse("cm-root@server.example.com:22");
        let rendered = match &parts.user {
            Some(user) => format!("{user}@{}", parts.host),
            None => parts.host.clone(),
        };
        assert_eq!(rendered, "root@server.example.com");
    }

    #[test]
    fn parse_no_prefix_still_splits() {
        assert_eq!(ControlName::parse("user@host:22").host, "host");
        assert_eq!(ControlName::parse("some-host:22").host, "some-host");
        assert_eq!(ControlName::parse(".cm-host:22").host, ".cm-host");
    }

    #[test]
    fn parse_long_and_multi_at_names() {
        let long_host = "a".repeat(256);
        assert_eq!(
            ControlName::parse(&format!("cm-user@{long_host}:22")).host,
            long_host
        );
        assert!(
            ControlName::parse("cm-user@host@extra:22")
                .host
                .contains("host@extra")
        );
    }

    #[test]
    fn pid_tails() {
        assert_eq!(pid_from_tail("ssh-abc123-48291"), Some(48291));
        assert_eq!(pid_from_tail("cm-user@host:22"), None);
        assert_eq!(pid_from_tail("ssh-hash-0"), None);
        assert_eq!(pid_from_tail("nodash"), None);
        assert_eq!(pid_from_tail("ssh-hash-abc"), None);
        assert_eq!(pid_from_tail("ssh-abc-def-123"), Some(123));
        assert_eq!(pid_from_tail("ssh-hash-00123"), Some(123));
        assert_eq!(pid_from_tail("ssh-hash-4294967295"), Some(4_294_967_295));
        assert_eq!(pid_from_tail("ssh-abc-99999999999"), None);
    }

    #[cfg(unix)]
    #[test]
    fn collect_finds_all_four_prefixes_in_one_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        make_socket_file(&dir.path().join("cm-alice@host:22"));
        make_socket_file(&dir.path().join("control-bob@host:22"));
        make_socket_file(&dir.path().join("mux-carol@host:22"));
        make_socket_file(&dir.path().join("ctrl-dave@host:22"));

        let mut found =
            collect_control_candidates(dir.path(), &["cm-", "control-", "mux-", "ctrl-"], true)
                .expect("collect");
        found.sort_by_key(|c| c.path.clone());
        assert_eq!(found.len(), 4, "all four prefixes must match in one pass");
        assert!(found.iter().all(|c| c.path.starts_with(dir.path())));
        assert!(found.iter().all(|c| c.kind == ControlCandidateKind::Socket));
    }

    #[cfg(unix)]
    #[test]
    fn collect_respects_the_prefix_set_it_is_given() {
        let dir = tempfile::tempdir().expect("tempdir");
        make_socket_file(&dir.path().join("cm-keep@host:22"));
        make_socket_file(&dir.path().join("ssh-other-hash-1"));

        let found =
            collect_control_candidates(dir.path(), &["cm-", "control-", "mux-", "ctrl-"], true)
                .expect("collect");
        assert_eq!(
            found.len(),
            1,
            "only the cm- candidate may be returned: {found:?}"
        );
        assert!(found[0].path.ends_with("cm-keep@host:22"));
    }

    #[test]
    fn collect_missing_dir_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");
        assert_eq!(
            collect_control_candidates(&missing, &["cm-"], true).expect("collect"),
            Vec::new()
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_plain_file_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("cm-user@myhost:22"), b"").expect("write candidate");
        std::fs::write(dir.path().join("cm-user@host.pub"), b"").expect("write dotted");
        std::fs::write(dir.path().join("control-user@host"), "x".repeat(2048)).expect("write big");

        let with_plain =
            collect_control_candidates(dir.path(), &["cm-", "control-"], true).expect("collect");
        assert_eq!(
            with_plain.len(),
            1,
            "only the small dotless file: {with_plain:?}"
        );
        assert_eq!(with_plain[0].kind, ControlCandidateKind::PlainFile);

        let sockets_only =
            collect_control_candidates(dir.path(), &["cm-", "control-"], false).expect("collect");
        assert_eq!(sockets_only.len(), 0, "plain files must be dropped");
    }

    #[cfg(unix)]
    #[test]
    fn collect_with_accepts_arbitrary_predicates() {
        let dir = tempfile::tempdir().expect("tempdir");
        make_socket_file(&dir.path().join("deploy@web01:22"));
        make_socket_file(&dir.path().join("unrelated"));

        let found = collect_control_candidates_with(dir.path(), |name| name.contains('@'), false)
            .expect("collect");
        assert_eq!(found.len(), 1, "only the @-carrying socket: {found:?}");
        assert!(found[0].path.ends_with("deploy@web01:22"));
    }
}
