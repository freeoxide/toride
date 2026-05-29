# Fail2Ban Rust Library Plan

## Product shape

Build a Rust crate that lets other Rust projects safely configure, validate, control, and diagnose an existing Fail2Ban installation.

This is **not** a full Fail2Ban replacement and **not** a full CLI product. It is a library/package/crate that apps can embed.

The crate should expose a typed Rust API for:

* creating/updating/removing Fail2Ban jails
* creating/updating/removing filters
* creating/updating/removing actions
* manual ban/unban operations
* status and statistics reads
* regex validation
* config validation
* reload/restart workflows
* doctor checks for permissions, service health, backend issues, log paths, actions, and firewall readiness

## Main design rule

Use existing battle-tested solutions first.

Do not hand-roll shell execution, INI mutation, process timeout handling, file locking, atomic writes, IP/CIDR parsing, service control, or firewall parsing unless no decent crate exists.

Primary philosophy:

> Fail2Ban already solved log scanning and banning. Our crate should manage and verify Fail2Ban, not reimplement it.

## Primary mode

The default backend is `fail2ban-client`.

The crate should call the official Fail2Ban command surface through a safe process runner. Do not talk directly to Fail2Ban’s socket or SQLite database in v1 unless there is a strong reason.

Runtime operations should be wrappers around commands like:

* `fail2ban-client ping`
* `fail2ban-client status`
* `fail2ban-client status <jail>`
* `fail2ban-client --test`
* `fail2ban-client reload`
* `fail2ban-client reload <jail>`
* `fail2ban-client set <jail> banip <ip>`
* `fail2ban-client set <jail> unbanip <ip>`
* `fail2ban-client banned`
* `fail2ban-client get dbfile`
* `fail2ban-client get logtarget`
* `fail2ban-client --str2sec <duration>`

Use `fail2ban-regex` for filter testing.

## Non-goals

Do not build:

* a new firewall engine
* a new log watcher
* a new regex engine
* a dashboard
* a full CLI app
* a replacement daemon
* package-manager installers as the default behavior
* direct root escalation
* arbitrary shell string execution by default

Optional tiny example binaries are fine for testing, but the product is the library API.

## Crate name ideas

Possible names:

* `fail2ban-kit`
* `fail2ban-rs`
* `fail2ban-control`
* `f2bkit`
* `fail2ban-manager`

Best clean name: `fail2ban-kit`.

## Workspace layout

```text
fail2ban-kit/
  crates/
    fail2ban-kit/
      src/
        lib.rs
        client.rs
        command.rs
        config.rs
        spec.rs
        render.rs
        doctor.rs
        regex_test.rs
        service.rs
        firewall.rs
        paths.rs
        error.rs
        report.rs
    fail2ban-kit-test-support/
      src/
        fake_runner.rs
        fixtures.rs
  examples/
    embed_myapp.rs
    doctor_report.rs
  tests/
    fixtures/
      jail/
      filter/
      action/
      logs/
```

Keep one main public crate. Split test support only if needed.

## Public API target

The library should feel like this conceptually:

```rust
let f2b = Fail2Ban::system();

let spec = JailSpec::builder("myapp")
    .filter(FilterSpec::named("myapp-auth"))
    .log_path("/var/log/myapp/auth.log")
    .backend(Backend::Auto)
    .bantime("10m")
    .findtime("10m")
    .maxretry(5)
    .action(ActionSpec::stock("nftables-multiport"))
    .build();

f2b.ensure_jail(spec)?;
f2b.test_config()?;
f2b.reload_jail("myapp")?;

let report = f2b.doctor(DoctorScope::all())?;
```

Real API can be different, but this is the ergonomic direction.

## Core modules

### `command`

Responsible for process execution.

Use:

* `duct` v1.1+ for command execution (built-in timeout via `.timeout()`)
* `which` to locate binaries
* no raw `std::process::Command` scattered around the codebase

Requirements:

* command args must be passed as arrays
* no shell string by default
* timeout per command
* capture stdout/stderr
* structured error type
* dry-run mode
* redacted command logs
* fake runner for tests

### `client`

Typed wrapper around `fail2ban-client`.

Public operations:

* `ping()`
* `version()`
* `test_config()`
* `reload()`
* `reload_jail(jail)`
* `restart_jail(jail, unban)`
* `status()`
* `status_jail(jail)`
* `statistics()`
* `banned()`
* `banned_ip(ip)`
* `ban_ip(jail, ip)`
* `unban_ip(jail, ip)`
* `add_ignore_ip(jail, ip_or_cidr)`
* `remove_ignore_ip(jail, ip_or_cidr)`
* `get_logtarget()`
* `get_dbfile()`
* `get_dbpurgeage()`
* `str_to_seconds(value)`

Do not parse free-form command output too aggressively in v1. Start with stable wrappers returning raw output plus basic parsed summaries.

### `config`

Responsible for reading and writing Fail2Ban config snippets.

Do not edit:

* `/etc/fail2ban/jail.conf`
* `/etc/fail2ban/fail2ban.conf`
* stock files in `/etc/fail2ban/filter.d/*.conf`
* stock files in `/etc/fail2ban/action.d/*.conf`

Write only owned files:

```text
/etc/fail2ban/jail.d/<namespace>.local
/etc/fail2ban/filter.d/<namespace>-<filter>.local
/etc/fail2ban/action.d/<namespace>-<action>.local
```

Default namespace example:

```text
managed-by-fail2ban-kit
```

Each generated file must include a header:

```ini
# Managed by fail2ban-kit.
# Do not edit manually unless you also disable this manager.
```

Use atomic writes and file locking.

Use backups before replacing files:

```text
/etc/fail2ban/jail.d/myapp.local.bak-2026-05-29T...
```

### `spec`

Strongly typed Rust model.

Types:

* `JailName`
* `FilterName`
* `ActionName`
* `Backend`
* `JailSpec`
* `FilterSpec`
* `ActionSpec`
* `DurationSpec`
* `PortSpec`
* `Protocol`
* `IpOrCidr`
* `LogPath`
* `JournalMatch`
* `RegexLine`
* `IgnoreIpList`

Validation rules:

* jail/filter/action names must reject `/`, `..`, newline, shell metacharacters
* generated paths must stay inside configured Fail2Ban directories
* `backend = systemd` must use `journalmatch`, not `logpath`
* file-log backends must have at least one `logpath`
* `maxretry > 0`
* `findtime > 0`
* `bantime` may allow negative/permanent only if explicitly enabled
* `usedns = no` should be the secure default for app logs
* IPs and CIDRs should be parsed with an existing IP crate

### `render`

Render typed specs into Fail2Ban-compatible INI.

Important: Fail2Ban config is INI-like but has Python interpolation, multi-line values, includes, and action/filter syntax. Do not assume generic INI round-tripping will be perfect.

Recommended approach:

* for generated files, render from typed structs
* for existing files, read minimally or treat as external
* do not rewrite unknown human files
* snapshot-test generated config output

### `regex_test`

Wrapper around `fail2ban-regex`.

Use it to test:

* a raw log line against a raw failregex
* a log file against a filter file
* a systemd journal query against a filter
* ignoreregex behavior
* datepattern behavior
* maxlines behavior

Do not validate Fail2Ban regexes using Rust `regex` as the source of truth. Rust regex syntax is not the same as Fail2Ban’s Python regex behavior.

### `service`

Service manager layer.

v1 can use `systemctl` through the same command runner.

Optional feature flags:

```toml
features = {
  systemd-zbus = ["zbus_systemd"],
  service-manager = ["service-manager"]
}
```

Operations:

* `is_active()`
* `is_enabled()`
* `start()`
* `stop()`
* `restart()`
* `reload_or_restart()`
* `journal_tail()`

Keep service-control optional because many apps should only manage config and ask the deploy system to reload.

### `firewall`

Mostly diagnostic in v1.

Do not manually insert firewall rules unless there is a dedicated advanced feature.

Doctor should inspect:

* `nft` exists if nftables action is configured
* `iptables`/`ip6tables` exists if iptables action is configured
* current Fail2Ban chains/sets are present after jail start
* IPv6 ban support exists when IPv6 addresses are used
* backend action name matches available system tools

Optional future support:

* parse `nft --json list ruleset`
* parse iptables rules
* expose read-only firewall state

### `doctor`

The most important differentiator.

Return structured findings, not just text.

Types:

```rust
enum Severity {
    Ok,
    Info,
    Warning,
    Error,
    Critical,
}

struct Finding {
    id: &'static str,
    severity: Severity,
    title: String,
    detail: String,
    fix: Option<String>,
}
```

Doctor categories:

#### Binary checks

* `fail2ban-client` exists
* `fail2ban-regex` exists
* Fail2Ban version detected
* `systemctl` or selected service manager exists
* `nft`, `iptables`, `ip6tables` availability based on configured actions

#### Service checks

* Fail2Ban service active
* Fail2Ban service enabled
* `fail2ban-client ping` succeeds
* socket file exists if configured
* pid file exists if configured
* log target accessible
* database file path readable

#### Config checks

* config directory exists
* generated files exist
* generated files parse
* `fail2ban-client --test` passes
* `.local` override order is sane
* no stock `.conf` file was modified by our crate
* generated files contain the managed header
* stale backup files are not excessive

#### Jail checks

* jail exists
* jail enabled
* jail status is readable
* jail has a filter
* jail has at least one action
* jail has sane `bantime`
* jail has sane `findtime`
* jail has sane `maxretry`
* `usedns = no` recommended for app logs
* ignore list includes required safe addresses/CIDRs if configured
* runtime jail state matches persisted config after reload

#### Log path checks

* log path exists
* parent directory exists
* fail2ban process can read it
* glob patterns match at least one file
* warn that glob only covers files existing at startup
* log file is not empty when user expects activity
* log rotation path makes sense
* app actually logs real client IPs, not only proxy IPs
* Docker/container log paths are host-visible if Fail2Ban runs on host

#### Systemd journal checks

* backend is `systemd`
* `journalmatch` exists
* no `logpath` is used with systemd backend
* journal query returns recent rows
* service unit name exists
* Fail2Ban has access to journal

#### Regex checks

* failregex compiles via `fail2ban-regex`
* sample malicious lines match
* sample safe lines do not match
* ignoreregex excludes expected lines
* datepattern works
* multi-line regex has appropriate `maxlines`
* `<HOST>` appears correctly
* regex does not match usernames or random strings as IPs

#### Action checks

* action file exists
* action has ban and unban behavior
* actioncheck passes where possible
* action timeout configured
* action name resolves to stock or generated action
* action is compatible with system firewall backend
* email/webhook actions have required parameters if used
* Cloudflare/API actions warn if credentials are missing

#### Permission checks

* `/etc/fail2ban` is not world-writable
* generated config files are not world-writable
* generated files are owned by root or expected admin user
* directories have safe permissions
* backup files have safe permissions
* log file permissions allow Fail2Ban to read
* database file is not world-writable
* socket path permissions are sane
* app-managed files do not expose API secrets

#### Safety checks

* dry-run available before apply
* backup exists before destructive update
* rollback path available
* reload strategy chosen
* restart-with-unban requires explicit opt-in
* permanent bans require explicit opt-in
* self-ban protection configured if caller provides trusted IPs
* private networks can be ignored if requested

#### Proxy checks

For apps behind Traefik, NGINX, Cloudflare, or a VPS proxy:

* detect whether logs contain proxy IPs only
* warn if Fail2Ban would ban Cloudflare/Traefik instead of attacker
* support typed docs for real-IP logging requirements
* optional generated filters for Traefik access logs
* optional Cloudflare action should be separate and explicit

## Existing crate choices

### Process execution

Use:

* `duct` v1.1+ (has built-in timeout via `.timeout()`)

Optional:

* `which` to locate binaries

Avoid:

* `process_control` / `wait-timeout` — `duct` already handles timeouts
* raw repeated `std::process::Command`
* shell string concatenation
* `sh -c` unless explicitly required and gated

### Paths and filesystem

Use:

* `camino` for UTF-8 paths
* `atomic-write-file` for atomic writes
* `fd-lock` for file locks (actively maintained; `fs2` is stale since 2018)
* `tempfile` for temporary files and backup naming
* `walkdir` for scanning managed files
* `globset` for logpath checks (by BurntSushi, 176M+ downloads)

### Config rendering

Use:

* `serde`
* `serde_json`
* `toml` only for our own app-facing config, not Fail2Ban output
* `indoc` for clean multi-line templates
* snapshot tests for generated INI

Be careful with generic INI crates because Fail2Ban config has interpolation and multi-line semantics. Rendering our own generated snippets is safer than mutating arbitrary existing Fail2Ban config.

### IP handling

Use:

* `ipnet` — sufficient for IP/CIDR parsing and overlap checks via `.contains()` and `.overlaps()`

Optional:

* `iprange` only if interval-tree performance needed for large ignore lists (last updated 2022)

### Durations

Use Fail2Ban itself for exact validation where possible:

* `fail2ban-client --str2sec`

For internal Rust parsing/display:

* `humantime` v2.3+ (363M+ downloads, actively maintained)

Do not use `parse_duration` — avoids conflicting duration semantics. Fail2Ban duration strings differ from Rust conventions. Always validate through `--str2sec` before applying.

### Service control

Default:

* `systemctl` through command runner

Optional:

* `zbus_systemd`
* `service-manager`

### Firewall diagnostics

Use:

* `nftables` v0.6+ for nft JSON inspection (supports `tokio` and `async-process` features)
* `iptables` crate only for diagnostic support if needed

Do not become a firewall abstraction crate in v1.

### Errors and reports

Use:

* `thiserror`
* `miette` optionally for rich human diagnostics
* `serde` for JSON report output
* `tracing` for internal logging

### Tests

Use:

* `insta` for snapshot tests
* `assert_fs` for filesystem fixtures
* `tempfile`
* `proptest`
* fake command runner
* Docker-based integration tests for real Fail2Ban behavior

## Feature flags

Recommended features:

```toml
default = ["client", "config", "doctor"]

client = []
config = []
doctor = []
regex-test = []
systemd = []
systemd-zbus = []
firewall-nft = []
firewall-iptables = []
serde = []
tokio = []
```

Avoid pulling heavy systemd/firewall dependencies by default.

## Apply workflow

All mutating operations should follow this flow:

1. validate typed spec
2. render generated files to memory
3. acquire config lock
4. read current managed files
5. compute diff
6. write backup
7. atomic write new files
8. run `fail2ban-client --test`
9. reload affected jail or full Fail2Ban
10. verify status
11. return structured apply report

If step 8, 9, or 10 fails:

1. restore backup
2. test config again
3. reload previous state if possible
4. return rollback report

## Remove workflow

Removing a jail/filter/action should be explicit.

Do not delete unknown files.

Remove only files with our managed header and matching namespace.

Steps:

1. verify target belongs to namespace
2. backup file
3. remove generated file
4. run config test
5. reload
6. verify jail removed or disabled

## Runtime vs persisted config

Expose both modes clearly.

Runtime-only:

* `ban_ip`
* `unban_ip`
* temporary `addignoreip`
* temporary `addfailregex`

Persisted:

* generated `.local` files
* reload required

Do not hide this distinction. It matters.

## Suggested public API surface

### `Fail2Ban`

Main entry point.

Methods:

* `system()`
* `with_paths(paths)`
* `with_runner(runner)`
* `with_dry_run(bool)`
* `client()`
* `doctor(scope)`
* `ensure_jail(spec)`
* `remove_jail(name)`
* `test_config()`
* `reload()`
* `reload_jail(name)`
* `ban_ip(jail, ip)`
* `unban_ip(jail, ip)`

### `JailSpec`

Fields:

* `name`
* `enabled`
* `filter`
* `actions`
* `backend`
* `log_paths`
* `journal_matches`
* `ports`
* `protocol`
* `bantime`
* `findtime`
* `maxretry`
* `ignore_ips`
* `usedns`
* `maxlines`
* `extra_options`

### `FilterSpec`

Fields:

* `name`
* `before`
* `after`
* `definition`
* `prefregex`
* `failregex`
* `ignoreregex`
* `datepattern`
* `journalmatch`
* `mode`
* `extra_options`

### `ActionSpec`

Fields:

* `name`
* `kind`
* `stock_name`
* `parameters`
* `actionstart`
* `actionstop`
* `actioncheck`
* `actionban`
* `actionunban`
* `timeout`

Default should prefer stock Fail2Ban actions.

Custom command actions should be advanced and explicitly enabled.

## Security model

The library may write root-owned system config, so it must be boring and strict.

Rules:

* no shell by default
* no arbitrary action command by default
* no path traversal
* no writing outside configured Fail2Ban directories
* no editing stock files
* no deleting files without managed header
* no restart-with-unban unless explicit
* no permanent ban unless explicit
* no package install unless optional and explicit
* no storing secrets in world-readable files
* no logging API tokens or action secrets

## MVP scope

MVP should include:

* binary discovery
* typed `Fail2BanClient`
* `ping`
* `version`
* `status`
* `status_jail`
* `ban_ip`
* `unban_ip`
* `test_config`
* `reload`
* typed `JailSpec`
* typed `FilterSpec`
* render managed jail/filter files
* atomic writes
* backups
* doctor report
* `fail2ban-regex` wrapper
* fake runner tests
* snapshot tests
* one real Docker integration test

Do not include custom firewall management in MVP.

## Nice-to-have v1.1

* nftables JSON inspection
* iptables inspection
* systemd D-Bus backend
* Traefik preset
* NGINX preset
* Axum app-log preset
* SSH preset using stock `sshd` filter
* Cloudflare action generator
* JSON doctor report
* markdown doctor report
* rollback API
* config diff API

## Presets

Presets should generate specs, not execute magic.

Possible presets:

* `Preset::Sshd`
* `Preset::NginxAuth`
* `Preset::NginxBadBots`
* `Preset::TraefikAuth`
* `Preset::AxumJsonAuthLog`
* `Preset::DockerContainerLog`
* `Preset::SystemdUnit`

Each preset should return a typed spec that the caller can inspect before applying.

## Testing plan

### Unit tests

* jail name validation
* filter name validation
* action name validation
* path traversal rejection
* IP/CIDR parsing
* duration validation
* backend/logpath/journalmatch validation
* config rendering
* command building
* output parsing

### Snapshot tests

Snapshot generated:

* jail `.local`
* filter `.local`
* action `.local`
* doctor report
* apply diff
* rollback report

### Fake command tests

Use a fake command runner to simulate:

* missing `fail2ban-client`
* failing `fail2ban-client --test`
* failing reload
* failed ban
* absent jail
* malformed status output
* timeout
* permission denied

### Integration tests

Run inside Docker where possible:

* install Fail2Ban
* create temporary config dir
* generate a jail
* test config
* reload
* write matching log line
* verify ban
* unban
* remove jail
* verify cleanup

Some tests will need to be marked ignored unless running as root or inside a privileged container.

## Documentation deliverables

The crate should ship:

* README with “library, not CLI” positioning
* safety model
* root permissions explanation
* quickstart
* doctor examples
* rollback examples
* preset examples
* testing Fail2Ban filters
* app logging format guide
* proxy/real-IP warning
* Docker/host logging notes
* feature flag table

## Final implementation order

### Sprint 1: Foundations

* crate skeleton
* error types
* command runner trait
* duct runner
* fake runner
* binary discovery
* basic `fail2ban-client` wrapper

### Sprint 2: Config generation

* typed specs
* validators
* renderer
* atomic write layer
* backup layer
* dry-run diff

### Sprint 3: Apply/reload

* `ensure_jail`
* `remove_jail`
* config test
* reload
* rollback on failure

### Sprint 4: Doctor

* binary checks
* service checks
* config checks
* jail checks
* permission checks
* logpath checks
* regex checks
* action checks

### Sprint 5: Integration quality

* Docker integration tests
* docs
* examples
* presets
* CI matrix

## Final audit checklist

Before calling v1 done, the crate must support:

* create jail
* update jail
* remove jail
* create filter
* update filter
* remove filter
* create action
* update action
* remove action
* ban IP
* unban IP
* list status
* list jail status
* run config test
* run regex test
* reload Fail2Ban
* reload one jail
* dry-run apply
* backup before write
* rollback after failed apply
* doctor report
* permission checks
* logpath checks
* systemd journal checks
* firewall backend checks
* IPv4 and IPv6 validation
* proxy/real-IP warning
* no stock config mutation
* no shell string command execution by default
* no deleting unmanaged files
