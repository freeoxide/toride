//! Daemon liveness and health checks.
//!
//! Reads PID files, checks `/proc` (Linux) or `kill -0` (macOS/Windows),
//! parses restart-count files, and detects stale Unix sockets.
//!
//! # Stale socket detection
//!
//! On Unix platforms, [`DaemonStatus::collect`] attempts to connect to the
//! daemon's Unix socket. If the connection is refused or times out, the
//! socket is flagged as stale so the caller can clean it up.
