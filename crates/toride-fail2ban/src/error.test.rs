//! Tests for the [`Error`] type and [`Result`] alias: construction of every
//! variant, human-readable `Display`, source preservation through
//! `#[from]`, and serde round-trips behind the `serde` feature.

use std::io::{self, ErrorKind};
use std::time::Duration;

use super::{Error, Result};

#[test]
fn io_variant_from_io_error() {
    let src = io::Error::new(ErrorKind::NotFound, "file gone");
    let err = Error::Io(src);
    assert!(matches!(err, Error::Io(_)));
}

#[test]
fn validation_variant() {
    let err = Error::Validation("port out of range".into());
    assert!(matches!(err, Error::Validation(_)));
}

#[test]
fn not_found_variant() {
    let err = Error::NotFound("sshd jail".into());
    assert!(matches!(err, Error::NotFound(_)));
}

#[test]
fn json_variant_from_serde_error() {
    let src = serde_json::from_str::<i32>("not a number").unwrap_err();
    let err = Error::Json(src);
    assert!(matches!(err, Error::Json(_)));
}

#[test]
fn command_timeout_variant() {
    let err = Error::CommandTimeout(Duration::from_secs(30));
    assert!(matches!(err, Error::CommandTimeout(_)));
}

#[test]
fn display_io() {
    let err = Error::Io(io::Error::new(ErrorKind::PermissionDenied, "access denied"));
    let msg = format!("{err}");
    assert!(msg.starts_with("I/O error:"), "got: {msg}");
    assert!(msg.contains("access denied"), "got: {msg}");
}

#[test]
fn display_validation() {
    let err = Error::Validation("bad port".into());
    assert_eq!(format!("{err}"), "validation error: bad port");
}

#[test]
fn display_not_found() {
    let err = Error::NotFound("jail sshd".into());
    assert_eq!(format!("{err}"), "not found: jail sshd");
}

#[test]
fn display_command_timeout_mentions_duration() {
    let err = Error::CommandTimeout(Duration::from_millis(1500));
    let msg = format!("{err}");
    assert!(
        msg.contains("1.5s"),
        "message should contain the duration: {msg}"
    );
}

#[test]
fn display_json() {
    let src = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
    let err = Error::Json(src);
    let msg = format!("{err}");
    assert!(msg.starts_with("JSON error:"), "got: {msg}");
}

#[test]
fn display_command_failed_has_no_em_dash() {
    let err = Error::CommandFailed("iptables blocked it".into());
    let msg = format!("{err}");
    assert!(
        !msg.contains('\u{2014}'),
        "consumer-visible error text must not contain em dashes: {msg}"
    );
}

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

#[test]
fn result_ok() {
    let res: Result<i32> = Ok(42);
    assert_eq!(res.unwrap(), 42);
}

#[test]
fn result_err() {
    let res: Result<i32> = Err(Error::InvalidConfig("oops".into()));
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(err, Error::InvalidConfig(ref s) if s == "oops"));
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

#[test]
fn debug_format_includes_variant_name() {
    let err = Error::InvalidConfig("bad".into());
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("InvalidConfig"),
        "Debug should include variant name: {dbg}"
    );
}

/// `#[non_exhaustive]` means external callers always need a wildcard arm;
/// this dispatch mirrors that shape for every variant.
#[test]
fn all_variants_dispatch_with_wildcard() {
    fn classify(err: &Error) -> &'static str {
        match err {
            Error::Io(_) => "io",
            Error::Json(_) => "json",
            Error::ConfigNotFound(_) => "config_not_found",
            Error::InvalidConfig(_) => "invalid_config",
            Error::InvalidIp(_) => "invalid_ip",
            Error::AlreadyBanned(_) => "already_banned",
            Error::NotBanned(_) => "not_banned",
            Error::InvalidRegex(_) => "invalid_regex",
            Error::LogFileError(_) => "log_file_error",
            Error::CommandFailed(_) => "command_failed",
            Error::CommandTimeout(_) => "command_timeout",
            Error::JailAlreadyExists(_) => "jail_already_exists",
            Error::JailNotFound(_) => "jail_not_found",
            Error::NotFound(_) => "not_found",
            Error::Validation(_) => "validation",
            Error::LockFailed(_) => "lock_failed",
            // Wildcard is required for external callers; within the crate
            // this is currently unreachable but guards against future variants.
            #[allow(unreachable_patterns)]
            _ => "unknown",
        }
    }

    let cases: Vec<(Error, &str)> = vec![
        (Error::Io(io::Error::new(ErrorKind::Other, "x")), "io"),
        (
            Error::Json(serde_json::from_str::<()>("{").unwrap_err()),
            "json",
        ),
        (Error::ConfigNotFound("c".into()), "config_not_found"),
        (Error::InvalidConfig("i".into()), "invalid_config"),
        (Error::InvalidIp("1.2.3".into()), "invalid_ip"),
        (Error::AlreadyBanned("a".into()), "already_banned"),
        (Error::NotBanned("n".into()), "not_banned"),
        (Error::InvalidRegex("r".into()), "invalid_regex"),
        (Error::LogFileError("l".into()), "log_file_error"),
        (Error::CommandFailed("f".into()), "command_failed"),
        (
            Error::CommandTimeout(Duration::from_secs(1)),
            "command_timeout",
        ),
        (Error::JailAlreadyExists("j".into()), "jail_already_exists"),
        (Error::JailNotFound("j".into()), "jail_not_found"),
        (Error::NotFound("n".into()), "not_found"),
        (Error::Validation("v".into()), "validation"),
        (Error::LockFailed("k".into()), "lock_failed"),
    ];

    for (err, expected) in cases {
        assert_eq!(classify(&err), expected, "mismatch for {err:?}");
    }
}

#[cfg(feature = "serde")]
mod serde_tests {
    use std::io::{self, ErrorKind};
    use std::time::Duration;

    use serde_json::Value;

    use super::super::Error;

    fn to_json(err: &Error) -> serde_json::Value {
        serde_json::to_value(err).expect("serialization should succeed")
    }

    #[test]
    fn serialize_is_object_with_type_and_detail() {
        let err = Error::InvalidConfig("missing bantime".into());
        let val = to_json(&err);

        assert!(val.is_object(), "serialized error should be a JSON object");
        assert_eq!(val["type"], "invalid_config");
        assert_eq!(val["detail"], "Invalid config value: missing bantime");
    }

    #[test]
    fn serialize_io_variant() {
        let err = Error::Io(io::Error::new(ErrorKind::NotFound, "file missing"));
        let val = to_json(&err);

        assert_eq!(val["type"], "io");
        assert!(val["detail"].as_str().unwrap().contains("file missing"));
    }

    #[test]
    fn serialize_command_timeout_variant() {
        let err = Error::CommandTimeout(Duration::from_secs(60));
        let val = to_json(&err);

        assert_eq!(val["type"], "command_timeout");
        assert!(
            val["detail"].as_str().unwrap().contains("60s"),
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
        for (err, expected_type) in [
            (Error::Validation("bad".into()), "validation"),
            (Error::NotFound("bad".into()), "not_found"),
            (Error::LockFailed("bad".into()), "lock_failed"),
            (Error::InvalidIp("bad".into()), "invalid_ip"),
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
