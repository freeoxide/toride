//! Comprehensive tests for the [`Error`] type and [`Result`] alias.
//!
//! Covers:
//! - Construction of every variant
//! - `Display` output is human-readable
//! - `Io` and `Json` variants preserve the source via `#[from]`
//! - `Result<T>` works for both `Ok` and `Err`
//! - `#[non_exhaustive]` is documented (cannot be matched exhaustively outside the crate)
//! - Serialization round-trips when the `serde` feature is enabled

use std::io::{self, ErrorKind};
use std::time::Duration;

use super::{Error, Result};

// -----------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------

#[test]
fn io_variant_from_io_error() {
    let src = io::Error::new(ErrorKind::NotFound, "file gone");
    let err = Error::Io(src);
    assert!(matches!(err, Error::Io(_)));
}

#[test]
fn command_variant_with_exit_code() {
    let err = Error::Command {
        program: "fail2ban-client".into(),
        code: Some(1),
        stderr: "jail not found".into(),
    };
    assert!(matches!(err, Error::Command { .. }));
}

#[test]
fn command_variant_without_exit_code() {
    let err = Error::Command {
        program: "nft".into(),
        code: None,
        stderr: String::new(),
    };
    assert!(matches!(err, Error::Command { .. }));
}

#[test]
fn config_variant() {
    let err = Error::Config("missing bantime".into());
    assert!(matches!(err, Error::Config(_)));
}

#[test]
fn validation_variant() {
    let err = Error::Validation("port out of range".into());
    assert!(matches!(err, Error::Validation(_)));
}

#[test]
fn regex_variant() {
    let err = Error::Regex("unclosed group".into());
    assert!(matches!(err, Error::Regex(_)));
}

#[test]
fn doctor_variant() {
    let err = Error::Doctor("check failed".into());
    assert!(matches!(err, Error::Doctor(_)));
}

#[test]
fn not_found_variant() {
    let err = Error::NotFound("sshd jail".into());
    assert!(matches!(err, Error::NotFound(_)));
}

#[test]
fn timeout_variant() {
    let err = Error::Timeout {
        program: "fail2ban-client".into(),
        duration: Duration::from_secs(30),
    };
    assert!(matches!(err, Error::Timeout { .. }));
}

#[test]
fn permission_denied_variant() {
    let err = Error::PermissionDenied("/etc/fail2ban/jail.conf".into());
    assert!(matches!(err, Error::PermissionDenied(_)));
}

#[test]
fn json_variant_from_serde_error() {
    let src = serde_json::from_str::<i32>("not a number").unwrap_err();
    let err = Error::Json(src);
    assert!(matches!(err, Error::Json(_)));
}

#[test]
fn parse_variant() {
    let err = Error::Parse("expected integer".into());
    assert!(matches!(err, Error::Parse(_)));
}

// -----------------------------------------------------------------------
// Display formatting
// -----------------------------------------------------------------------

#[test]
fn display_io() {
    let err = Error::Io(io::Error::new(ErrorKind::PermissionDenied, "access denied"));
    let msg = format!("{err}");
    assert!(msg.starts_with("I/O error:"), "got: {msg}");
    assert!(msg.contains("access denied"), "got: {msg}");
}

#[test]
fn display_command_with_code_and_stderr() {
    let err = Error::Command {
        program: "nft".into(),
        code: Some(2),
        stderr: " table not found ".into(),
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("`nft`"),
        "message should mention the program name: {msg}"
    );
    assert!(
        msg.contains("exited with status 2"),
        "message should mention exit code: {msg}"
    );
    assert!(
        msg.contains("table not found"),
        "message should include trimmed stderr: {msg}"
    );
}

#[test]
fn display_command_with_code_no_stderr() {
    let err = Error::Command {
        program: "iptables".into(),
        code: Some(1),
        stderr: String::new(),
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("exited with status 1"),
        "message should mention exit code: {msg}"
    );
    assert!(
        !msg.contains('\u{2014}'),
        "em-dash separator should not appear when stderr is empty: {msg}"
    );
}

#[test]
fn display_command_no_code() {
    let err = Error::Command {
        program: "fail2ban-client".into(),
        code: None,
        stderr: String::new(),
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("could not be started"),
        "message should indicate process could not start: {msg}"
    );
}

#[test]
fn display_config() {
    let err = Error::Config("missing bantime".into());
    assert_eq!(format!("{err}"), "config error: missing bantime");
}

#[test]
fn display_validation() {
    let err = Error::Validation("bad port".into());
    assert_eq!(format!("{err}"), "validation error: bad port");
}

#[test]
fn display_regex() {
    let err = Error::Regex("unclosed (".into());
    assert_eq!(format!("{err}"), "regex error: unclosed (");
}

#[test]
fn display_doctor() {
    let err = Error::Doctor("firewall missing".into());
    assert_eq!(format!("{err}"), "doctor error: firewall missing");
}

#[test]
fn display_not_found() {
    let err = Error::NotFound("jail sshd".into());
    assert_eq!(format!("{err}"), "not found: jail sshd");
}

#[test]
fn display_timeout() {
    let err = Error::Timeout {
        program: "fail2ban-client".into(),
        duration: Duration::from_secs(30),
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("`fail2ban-client`"),
        "message should mention program: {msg}"
    );
    assert!(
        msg.contains("30s"),
        "message should contain human-readable duration: {msg}"
    );
}

#[test]
fn display_permission_denied() {
    let err = Error::PermissionDenied("/etc/shadow".into());
    assert_eq!(format!("{err}"), "permission denied: /etc/shadow");
}

#[test]
fn display_json() {
    let src = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
    let err = Error::Json(src);
    let msg = format!("{err}");
    assert!(msg.starts_with("JSON error:"), "got: {msg}");
}

#[test]
fn display_parse() {
    let err = Error::Parse("expected u32".into());
    assert_eq!(format!("{err}"), "parse error: expected u32");
}

// -----------------------------------------------------------------------
// Source preservation (std::error::Error chain)
// -----------------------------------------------------------------------

#[test]
fn io_error_source_is_preserved() {
    let src = io::Error::new(ErrorKind::BrokenPipe, "pipe broke");
    let err = Error::Io(src);

    let source = std::error::Error::source(&err)
        .expect("Io variant should expose a source")
        .downcast_ref::<io::Error>()
        .expect("source should be io::Error");

    assert_eq!(source.kind(), ErrorKind::BrokenPipe);
    assert!(source.to_string().contains("pipe broke"));
}

#[test]
fn json_error_source_is_preserved() {
    let src = serde_json::from_str::<serde_json::Value>("!!!").unwrap_err();
    let original_msg = src.to_string();
    let err = Error::Json(src);

    let source = std::error::Error::source(&err)
        .expect("Json variant should expose a source")
        .downcast_ref::<serde_json::Error>()
        .expect("source should be serde_json::Error");

    assert_eq!(source.to_string(), original_msg);
}

// -----------------------------------------------------------------------
// Result<T> alias
// -----------------------------------------------------------------------

#[test]
fn result_ok() {
    let res: Result<i32> = Ok(42);
    assert_eq!(res.unwrap(), 42);
}

#[test]
fn result_err() {
    let res: Result<i32> = Err(Error::Config("oops".into()));
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::Config(ref s) if s == "oops"));
}

#[test]
fn result_propagates_with_question_mark() {
    fn inner() -> Result<String> {
        Ok("hello".into())
    }
    fn outer() -> Result<String> {
        let val = inner()?;
        Ok(format!("{val} world"))
    }
    assert_eq!(outer().unwrap(), "hello world");
}

#[test]
fn result_propagates_error_with_question_mark() {
    fn inner() -> Result<String> {
        Err(Error::NotFound("gone".into()))
    }
    fn outer() -> Result<String> {
        let _ = inner()?;
        unreachable!("should have returned early")
    }
    let err = outer().unwrap_err();
    assert!(matches!(err, Error::NotFound(ref s) if s == "gone"));
}

#[test]
fn io_error_converts_via_from() {
    fn fallible() -> Result<()> {
        Err(io::Error::new(ErrorKind::UnexpectedEof, "eof"))?;
        Ok(())
    }
    let err = fallible().unwrap_err();
    assert!(matches!(err, Error::Io(_)));
}

#[test]
fn json_error_converts_via_from() {
    fn fallible() -> Result<()> {
        let _: i32 = serde_json::from_str("not json")?;
        Ok(())
    }
    let err = fallible().unwrap_err();
    assert!(matches!(err, Error::Json(_)));
}

// -----------------------------------------------------------------------
// Debug output
// -----------------------------------------------------------------------

#[test]
fn debug_format_includes_variant_name() {
    let err = Error::Config("bad".into());
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("Config"),
        "Debug should include variant name: {dbg}"
    );
}

// -----------------------------------------------------------------------
// #[non_exhaustive] documentation
// -----------------------------------------------------------------------

// NOTE: `#[non_exhaustive]` means that downstream crates cannot match
// exhaustively on `Error`. A wildcard `_` arm is always required.
// Within this crate (where the attribute does not enforce exhaustiveness)
// we can still match exhaustively, so we verify the intent indirectly:
// the enum compiles, and any _new_ variant added later will not break
// callers who included a wildcard arm.

/// This test demonstrates that every variant can be dispatched through a
/// match with a wildcard fallback, which is how external callers must
/// handle the enum.
#[test]
fn all_variants_dispatch_with_wildcard() {
    fn classify(err: &Error) -> &'static str {
        match err {
            Error::Io(_) => "io",
            Error::Command { .. } => "command",
            Error::Config(_) => "config",
            Error::Validation(_) => "validation",
            Error::Regex(_) => "regex",
            Error::Doctor(_) => "doctor",
            Error::NotFound(_) => "not_found",
            Error::Timeout { .. } => "timeout",
            Error::PermissionDenied(_) => "permission_denied",
            Error::Json(_) => "json",
            Error::Parse(_) => "parse",
            // Wildcard is required for external callers; within the crate
            // this is currently unreachable but guards against future variants.
            #[allow(unreachable_patterns)]
            _ => "unknown",
        }
    }

    let cases: Vec<(Error, &str)> = vec![
        (Error::Io(io::Error::new(ErrorKind::Other, "x")), "io"),
        (
            Error::Command {
                program: "p".into(),
                code: None,
                stderr: String::new(),
            },
            "command",
        ),
        (Error::Config("c".into()), "config"),
        (Error::Validation("v".into()), "validation"),
        (Error::Regex("r".into()), "regex"),
        (Error::Doctor("d".into()), "doctor"),
        (Error::NotFound("n".into()), "not_found"),
        (
            Error::Timeout {
                program: "t".into(),
                duration: Duration::from_secs(1),
            },
            "timeout",
        ),
        (Error::PermissionDenied("p".into()), "permission_denied"),
        (
            Error::Json(serde_json::from_str::<()>("{").unwrap_err()),
            "json",
        ),
        (Error::Parse("p".into()), "parse"),
    ];

    for (err, expected) in cases {
        assert_eq!(classify(&err), expected, "mismatch for {err:?}");
    }
}

// -----------------------------------------------------------------------
// Serde serialization (gated behind the `serde` feature)
// -----------------------------------------------------------------------

#[cfg(feature = "serde")]
mod serde_tests {
    use std::io::{self, ErrorKind};
    use std::time::Duration;

    use serde_json::Value;

    use super::super::{Error, Result};

    /// Helper: serialize an error, parse the JSON, and return it.
    fn to_json(err: &Error) -> serde_json::Value {
        serde_json::to_value(err).expect("serialization should succeed")
    }

    #[test]
    fn serialize_is_object_with_type_and_detail() {
        let err = Error::Config("missing bantime".into());
        let val = to_json(&err);

        assert!(val.is_object(), "serialized error should be a JSON object");
        assert_eq!(val["type"], "config");
        assert_eq!(val["detail"], "config error: missing bantime");
    }

    #[test]
    fn serialize_io_variant() {
        let err = Error::Io(io::Error::new(ErrorKind::NotFound, "file missing"));
        let val = to_json(&err);

        assert_eq!(val["type"], "io");
        assert!(val["detail"].as_str().unwrap().contains("file missing"));
    }

    #[test]
    fn serialize_command_variant() {
        let err = Error::Command {
            program: "nft".into(),
            code: Some(1),
            stderr: "error msg".into(),
        };
        let val = to_json(&err);

        assert_eq!(val["type"], "command");
        let detail = val["detail"].as_str().unwrap();
        assert!(
            detail.contains("nft"),
            "detail should mention program: {detail}"
        );
        assert!(
            detail.contains("1"),
            "detail should mention exit code: {detail}"
        );
    }

    #[test]
    fn serialize_timeout_variant() {
        let err = Error::Timeout {
            program: "slow".into(),
            duration: Duration::from_secs(60),
        };
        let val = to_json(&err);

        assert_eq!(val["type"], "timeout");
        assert!(
            val["detail"].as_str().unwrap().contains("1m"),
            "detail should mention duration: {}",
            val["detail"]
        );
    }

    #[test]
    fn serialize_json_variant() {
        let src = serde_json::from_str::<Value>("}invalid").unwrap_err();
        let err = Error::Json(src);
        let val = to_json(&err);

        assert_eq!(val["type"], "json");
        assert!(val["detail"].as_str().unwrap().starts_with("JSON error:"));
    }

    #[test]
    fn serialize_all_string_variants() {
        // String-only variants share the same shape; spot-check a few.
        for (err, expected_type) in [
            (Error::Validation("bad".into()), "validation"),
            (Error::Regex("bad".into()), "regex"),
            (Error::Doctor("bad".into()), "doctor"),
            (Error::NotFound("bad".into()), "not_found"),
            (Error::PermissionDenied("bad".into()), "permission_denied"),
            (Error::Parse("bad".into()), "parse"),
        ] {
            let val = to_json(&err);
            assert_eq!(val["type"], expected_type, "type mismatch for {err:?}");
            assert!(
                val["detail"].is_string(),
                "detail should be a string for {err:?}"
            );
        }
    }

    #[test]
    fn serialized_output_has_exactly_two_fields() {
        let err = Error::NotFound("something".into());
        let val = to_json(&err);
        let obj = val.as_object().expect("should be an object");
        assert_eq!(
            obj.len(),
            2,
            "serialized error should have exactly 'type' and 'detail' fields"
        );
        assert!(obj.contains_key("type"));
        assert!(obj.contains_key("detail"));
    }
}
