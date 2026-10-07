# toride-fail2ban

[![crates.io](https://img.shields.io/crates/v/toride-fail2ban.svg)](https://crates.io/crates/toride-fail2ban)
[![docs.rs](https://docs.rs/toride-fail2ban/badge.svg)](https://docs.rs/toride-fail2ban)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

A Rust library for programmatically managing an existing Fail2Ban installation.

## Positioning

This is a **Rust library crate**, not a CLI tool or Fail2Ban replacement. It lets Rust applications safely configure, validate, control, and diagnose an existing Fail2Ban installation through a typed, testable API.

## Safety model

All operations adhere to these security rules:

- **No shell injection** -- arguments are passed as arrays through the [`Runner`](src/command.rs) trait. No string concatenation into shell commands.
- **No path traversal** -- [`LogPath`](src/spec.rs) and name newtypes (`JailName`, `FilterName`, `ActionName`) reject `..` components and `/` characters on construction.
- **No stock config mutation** -- only `.local` override files are written. Files without the managed header are never overwritten. Stock `.conf` files are never modified.
- **No unsafe code** -- `#![deny(unsafe_code)]` is enforced at the crate level.
- **Sensitive value redaction** -- arguments containing "password", "token", "key", or "secret" are redacted in log output.
- **Atomic writes** -- config files are written via `tempfile` + atomic rename, so readers never see partial content.
- **Advisory locking** -- concurrent writes are coordinated via `fd-lock` to prevent conflicting updates.
- **Permanent ban gating** -- `bantime = "permanent"` requires explicit `allow_permanent_ban` opt-in on [`JailSpec`].
- **Validated names** -- all jail, filter, and action names reject shell metacharacters (`;`, `|`, `&`, `$`, backtick, quotes, parentheses, braces).
- **`<HOST>` enforcement** -- every [`RegexLine`](src/spec.rs) must contain the `<HOST>` placeholder, ensuring Fail2Ban can extract the offending IP.

## Root permissions

Writing to `/etc/fail2ban` requires elevated privileges. Any application using [`Fail2Ban::system()`] or [`IniManager::new`] to write jail, filter, or action configuration files must be run as root or via `sudo`. Read-only operations (doctor checks, status queries, regex testing) may work with reduced privileges depending on your Fail2Ban and systemd journal configuration.

The [`DoctorScope::Permission`] check will flag world-writable config directories and non-root-owned files. The [`DoctorScope::Safety`] check verifies that the config directory is writable so rollback operations can succeed.

## Quickstart

```rust
use toride_fail2ban::{Fail2Ban, spec::{JailSpec, FilterSpec, ActionSpec}};

// Connect to the system Fail2Ban installation.
let f2b = Fail2Ban::system()?;

// Validate the current configuration.
f2b.test_config()?;

// Build a jail spec with compile-time field checking.
let jail = JailSpec::builder()
    .name("myapp".parse()?)
    .filter(FilterSpec::named("myapp-filter")?)
    .action(ActionSpec::stock("nftables-multiport")?)
    .log_paths(vec!["/var/log/myapp/access.log".parse()?])
    .bantime("10m".parse()?)
    .findtime("5m".parse()?)
    .maxretry(5)
    .build();

// Write config, validate, and reload in one call.
let report = f2b.ensure_jail(jail)?;
if report.test_passed {
    println!("Jail applied successfully.");
} else {
    for finding in &report.findings {
        eprintln!("[{}] {}", finding.severity, finding.title);
    }
}

// Manually ban or unban IPs.
f2b.ban_ip("myapp", "203.0.113.50")?;
f2b.unban_ip("myapp", "203.0.113.50")?;

// Dry-run mode: log commands without executing them.
let f2b_dry = Fail2Ban::system()?.with_dry_run(true);
```

## Doctor examples

The [`Doctor`] runs structured diagnostic checks and returns a [`DoctorReport`] with typed [`Finding`] values.

```rust
use toride_fail2ban::{Fail2Ban, doctor::DoctorScope, report::Severity};

let f2b = Fail2Ban::system()?;

// Run all diagnostic categories.
let report = f2b.doctor(DoctorScope::All)?;

if report.has_critical() {
    for finding in &report.findings {
        if finding.severity >= Severity::Critical {
            eprintln!(
                "[{}] {} -- {}",
                finding.severity, finding.title,
                finding.fix.as_deref().unwrap_or("no fix suggested")
            );
        }
    }
}

// Group findings by severity for summary display.
let by_severity = report.summary_by_severity();
for (severity, findings) in &by_severity {
    println!("{severity}: {} finding(s)", findings.len());
}

// Run a single category.
let binary_report = f2b.doctor(DoctorScope::Binary)?;
let jail_report = f2b.doctor(DoctorScope::Jail("sshd".into()))?;
```

Available scopes: `All`, `Binary`, `Service`, `Config`, `Jail(name)`, `LogPath`, `Journal`, `Regex`, `Action`, `Permission`, `Safety`, `Proxy`.

## Rollback examples

[`ensure_jail`] writes config, validates, and reloads. When a step fails, the [`ApplyReport`] contains findings that describe what went wrong. The [`IniManager`] creates timestamped backups (`.bak-{timestamp}`) before overwriting, enabling manual rollback.

```rust
use toride_fail2ban::{Fail2Ban, spec::JailSpec};

let f2b = Fail2Ban::system()?;

let jail = JailSpec::builder()
    .name("myapp".parse()?)
    .filter(/* ... */)
    .bantime("10m".parse()?)
    .findtime("5m".parse()?)
    .build();

let report = f2b.ensure_jail(jail)?;

if !report.test_passed {
    eprintln!("Config test failed after writing jail.");
    for finding in &report.findings {
        eprintln!("  [{}] {}", finding.severity, finding.title);
    }
    // Backups were created at the paths in report.backup_paths.
    // Restore manually or remove the jail to roll back.
    eprintln!("Backup files: {:?}", report.backup_paths);
}

// Remove a managed jail entirely (restores backup if available).
let remove_report = f2b.remove_jail("myapp")?;
println!("Removed {} file(s)", remove_report.files_removed.len());
```

The [`RollbackReport`] type is returned by the `IniManager` when a write operation triggers an automatic restore from backup.

## Preset examples

Presets -- pre-built [`JailSpec`] configurations for common services (SSH, Nginx, Apache, Postfix, Dovecot, etc.) -- are planned for v1.1. They will provide battle-tested defaults that can be applied with minimal customization:

```rust
// Planned API (not yet available):
// use toride_fail2ban::preset;
// let jail = preset::ssh_default()?;
// f2b.ensure_jail(jail)?;
```

For now, build specs manually using [`JailSpec::builder()`] with the values from your service's documentation.

## Testing Fail2Ban filters

The [`RegexTester`] wraps `fail2ban-regex` to validate filter patterns against sample log lines. It uses the actual `fail2ban-regex` binary (not Rust's regex crate) because Fail2Ban uses Python regex syntax.

```rust
use toride_fail2ban::Fail2Ban;

let f2b = Fail2Ban::system()?;
let tester = f2b.regex_tester()?;

// Test a single log line against a failregex.
let result = tester.test_line(
    r"sshd\[\d+\]: Failed password for .* from <HOST>",
    "Mar  1 12:00:00 host sshd[1234]: Failed password for root from 10.0.0.1",
)?;
println!(
    "Matched {} of {} lines ({:.0}%)",
    result.lines_matched,
    result.lines_processed,
    result.match_rate() * 100.0
);

// Test a filter config file against a log file.
let result = tester.test_filter_file(
    std::path::Path::new("/etc/fail2ban/filter.d/sshd.conf"),
    std::path::Path::new("/var/log/auth.log"),
)?;

// Test a custom datepattern.
let result = tester.test_datepattern(
    "{^LN-BEG}",
    "2024-01-15 10:30:00 [ERROR] login failed from <HOST>",
    r"login failed from <HOST>",
)?;

// Test multi-line regex with maxlines.
let result = tester.test_maxlines(
    2,
    "line one\nline two with <HOST>",
    r"line one\n.*<HOST>",
)?;

// Test an ignoreregex pattern.
let result = tester.test_ignoreregex(
    r"my-health-check-bot",
    "10.0.0.1 - - [GET /healthz] my-health-check-bot",
)?;
// result.lines_matched > 0 means the line would be ignored by Fail2Ban.
```

## App logging format guide

For Fail2Ban to extract attacker IPs from your application logs, two requirements must be met:

### 1. Real IP in the log line

Your application must log the real client IP address in each log line. The IP must be the actual client IP, not the reverse proxy or load balancer IP. Use headers like `X-Forwarded-For` or `X-Real-IP` to extract the real IP.

Good:

```
2024-01-15 10:30:00 [ERROR] Authentication failed for user "admin" from 203.0.113.50
```

Bad (proxy IP only):

```
2024-01-15 10:30:00 [ERROR] Authentication failed for user "admin" from 10.0.0.1
```

### 2. `<HOST>` in the failregex

Every [`RegexLine`] must contain the `<HOST>` placeholder. This is enforced at construction time -- the library will reject any regex that does not include it. Fail2Ban uses `<HOST>` as an interpolation anchor to extract the offending IP address from matching log lines.

Example filter for a web application:

```ini
[Definition]
failregex = ^.*Authentication failed.*from <HOST>.*$
ignoreregex =
```

In Rust, construct the filter spec with a validated [`RegexLine`]:

```rust
use toride_fail2ban::spec::{FilterSpec, RegexLine};

let filter = FilterSpec::builder()
    .name("myapp".parse()?)
    .failregex(vec![
        RegexLine::new(r#"^.*Authentication failed.*from <HOST>.*$"#)?,
    ])
    .build();
```

## Proxy / real-IP warning

When your server sits behind a reverse proxy (NGINX, Traefik, HAProxy) or CDN (Cloudflare), the source IP in your application logs will be the **proxy's IP**, not the real client IP. Fail2Ban would then ban the proxy IP, which blocks **all** traffic through that proxy -- every legitimate user included.

The [`DoctorScope::Proxy`] check detects this scenario by inspecting log files for private-only IP addresses and warning about reverse proxy or CDN configurations.

To avoid this:

1. Configure your reverse proxy to pass the real client IP (e.g., `X-Forwarded-For`, `X-Real-IP`, or `CF-Connecting-IP` for Cloudflare).
2. Ensure your application logs the forwarded IP, not the proxy IP.
3. For Cloudflare, consider using the `cloudflare` Fail2Ban action to ban IPs via the Cloudflare API instead of local firewall rules.

## Docker / host logging notes

When Fail2Ban runs on the host and your application runs inside a Docker container, the container's log files are inside the container's filesystem and may not be visible to Fail2Ban on the host.

The [`DoctorScope::LogPath`] check detects log paths that appear to be inside Docker container filesystems (`/var/lib/docker/`, `/containers/`) and warns about visibility issues.

Solutions:

- **Bind-mount log files** from the container to the host (e.g., `-v /var/log/myapp:/var/log/myapp`).
- **Use syslog** -- configure the container to log to syslog, which is accessible on the host.
- **Use Docker logging drivers** -- the `json-file` or `local` drivers with host-mounted volumes make logs visible.
- **Run Fail2Ban inside the container** -- if your setup allows it, run Fail2Ban alongside the application in the same container or pod.

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `client` | Yes | [`Fail2BanClient`] wrapper around `fail2ban-client` commands |
| `config` | Yes | Config file reading and writing via [`IniManager`] |
| `doctor` | Yes | Diagnostic engine ([`Doctor`], [`DoctorScope`], [`DoctorReport`]) |
| `regex-test` | No | [`RegexTester`] wrapper around `fail2ban-regex` for filter testing |
| `systemd` | No | Systemd journal backend support |
| `systemd-zbus` | No | Direct D-Bus communication with systemd (planned, not yet implemented) |
| `firewall-nft` | No | Native nftables JSON ruleset inspection (planned, not yet implemented) |
| `firewall-iptables` | No | Native iptables rules parsing (planned, not yet implemented) |
| `serde` | No | JSON serialization for [`Error`] and report types |
| `tokio` | No | Async runtime support (planned) |

## Testing

The crate is designed for testability through the [`Runner`] trait. Inject a [`FakeRunner`] in tests to avoid needing a real Fail2Ban installation:

```rust
use toride_fail2ban::command::{FakeRunner, CommandOutput, Runner};
use toride_fail2ban::Fail2Ban;

let mut fake = FakeRunner::new();
fake.with_response("fail2ban-client", &["--test"], CommandOutput::empty_success());

let f2b = Fail2Ban::with_runner(Box::new(fake));
// All commands are recorded and return canned responses.
```

## License

MIT
