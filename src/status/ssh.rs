//! SSH subsystem status: mux master, control path, config parse, agent, keys.
//!
//! Uses `ssh -O check` to probe the mux master, validates control paths via
//! `fs::symlink_metadata`, and shells out to `ssh-keygen -L` for config
//! parsing. Key counting uses `ssh-add -l`.
//!
//! # Control path validation
//!
//! The control path must satisfy **all** of:
//!
//! 1. Exist and be a Unix socket (or named pipe on Windows).
//! 2. Have permissions `0600` (owner read/write only).
//! 3. Be connectable (non-blocking `UnixStream::connect`).
//! 4. Have a valid, non-expired `CtlTimeMs` (if the mux supports it).
