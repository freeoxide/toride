# VPS Security Crate Split: Design Document

> **Status:** Draft v2
> **Date:** 2026-06-01
> **Scope:** Shared abstractions extraction + new VPS security crates

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Shared Abstractions (Prerequisite)](#shared-abstractions-prerequisite)
3. [New VPS Security Crates](#new-vps-security-crates)
4. [Architecture Decisions](#architecture-decisions)
5. [Full Workspace Structure](#full-workspace-structure)
6. [Implementation Order](#implementation-order)
7. [Dependency Graph](#dependency-graph)
8. [Convention Reference](#convention-reference)
9. [Appendix: Per-Crate Details](#appendix-per-crate-details)

---

## Executive Summary

### What exists today

| Domain | Crate | Status |
|--------|-------|--------|
| SSH management | `toride-ssh` (9 sub-crates) | ✅ Implemented |
| Firewall | `ufw-kit` | ✅ Implemented |
| Intrusion prevention | `toride-fail2ban` | ✅ Implemented |
| System status | `toride-status` | ✅ Implemented |

### What this document proposes

**Step 1: Extract 4 shared crates** from duplicated patterns found across all 13 existing crates (~950 lines saved):

| Crate | Extracts | Lines Saved |
|-------|----------|-------------|
| `toride-runner` | Runner trait, CommandSpec, DuctRunner, FakeRunner, redaction | ~350 |
| `toride-fs` | atomic writes, file locking, path expansion, permissions | ~280 |
| `toride-diagnostic-types` | Severity, Finding, binary/permission check helpers | ~120 |
| `toride-service` | systemd service management (is_active, start, stop, etc.) | ~200 |

**Step 2: Build 10 new VPS security crates** on top of the shared foundation.

### Key Decisions

1. **Extract shared crates first** — before building anything new, eliminate the 3-way Runner trait duplication and 9-way atomic_write duplication
2. **Runner is sync-only** — async bridging is each consumer's responsibility via `spawn_blocking`. No forced tokio dependency.
3. **Single crates with feature gates** over umbrella+sub-crate patterns — following the proven `ufw-kit` model
4. **Split VPN into two crates** — WireGuard (sync) and Tailscale (async/API) share nothing at the implementation level
5. **toride-diagnostic-types is minimal** — just Severity + Finding + helpers. The Check trait stays in toride-ssh-doctor.
6. **No premature test-support crates** — fixtures start internal

---

## Current Workspace Inventory

```
toride (binary+lib)                    # Main TUI application
├── toride-ssh (umbrella)              # SSH management facade
│   ├── toride-ssh-core               # Error, Runner, SshPaths, types
│   ├── toride-ssh-config             # ~/.ssh/config AST editing
│   ├── toride-ssh-key                # Key generation, inventory, repair
│   ├── toride-ssh-agent              # Agent key management
│   ├── toride-ssh-authorized-keys    # authorized_keys management
│   ├── toride-ssh-known-hosts        # known_hosts management
│   ├── toride-ssh-doctor             # SSH diagnostics
│   ├── toride-ssh-certificate        # CA/certificate/KRL operations
│   └── toride-ssh-forward            # Port forwarding
├── toride-status                      # System metrics & health
├── toride-fail2ban                    # Fail2Ban management
├── ufw-kit                            # UFW firewall management
└── ufw-kit-test-support               # Test utilities for ufw-kit
```

**Total: 16 crates** (1 binary, 15 libraries)

---

## Proposed New Crates

### Overview

| # | Crate | Priority | Type | Modules | Wraps |
|---|-------|----------|------|---------|-------|
| **Shared** | `toride-runner` | **P0** | Shared | ~7 | — |
| **Shared** | `toride-fs` | **P0** | Shared | ~6 | — |
| **Shared** | `toride-diagnostic-types` | **P0** | Shared | ~4 | — |
| **Shared** | `toride-service` | **P0** | Shared | ~3 | — |
| 1 | `toride-updates` | **P0** | Standalone | ~16 | `unattended-upgrades`, `dnf-automatic` |
| 2 | `toride-harden` | **P0** | Standalone | ~14 | `sysctl`, `mount`, `findmnt` |
| 3 | `toride-users` | **P1** | Standalone | ~16 | `useradd`, `visudo`, `google-authenticator` |
| 4 | `toride-wireguard` | **P1** | Standalone | ~12 | `wg`, `wg-quick` |
| 5 | `toride-audit` | **P1** | Standalone (features) | ~20 | `auditctl`, `aide`, `rsyslogd`, `logrotate` |
| 6 | `toride-proxy` | **P1** | Standalone (features) | ~18 | `nginx`, `caddy`, `certbot` |
| 7 | `toride-backup` | **P2** | Standalone | ~15 | `restic`, `borg` |
| 8 | `toride-cloud` | **P2** | Standalone | ~12 | `aws`, `gcloud`, `doctl`, `hcloud` |
| 9 | `toride-monitor` | **P2** | Standalone | ~14 | `iptables`, `conntrack`, `ss` |
| 10 | `toride-tailscale` | **P2** | Standalone | ~12 | `tailscale` API |

**Total after: 30 crates** (1 binary, 29 libraries) — up from 16 today.
**Shared crates save ~950 lines** of duplicated code across existing crates.

---

## Architecture Decisions

### 1. Extract shared crates BEFORE building new ones

The workspace has 3 Runner traits, 9 atomic_write implementations, and duplicated Severity/Finding types across all crates. Building 10 new crates on duplicated foundations would create a maintenance nightmare.

**Migration order:** `toride-service` → `toride-fs` → `toride-runner` → `toride-diagnostic-types` → then new crates

### 2. Runner is sync-only in the shared crate

ufw-kit has zero async dependencies. toride-ssh-core uses async_trait. Making the shared trait sync avoids forcing tokio on ufw-kit. SSH crates bridge via `spawn_blocking` (which they already do internally).

### 3. No umbrella crates for audit/proxy

The initial design proposed umbrella+sub-crate patterns (6 crates for audit, 4 for proxy). Rejected:
- `ufw-kit` proves single-crate works (24 modules, 16K+ lines, feature gates)
- Core crates become empty indirection when Runner is shared

### 4. WireGuard and Tailscale are separate crates

| Aspect | WireGuard | Tailscale |
|--------|-----------|-----------|
| Architecture | Local kernel interface | Cloud-managed HTTP API |
| Async required | No | Yes (reqwest) |
| Config | INI files | JSON via API |

### 5. toride-diagnostic-types is minimal

Just Severity + Finding + helpers. The Check trait and CheckRegistry are used exclusively by toride-ssh-doctor and stay there.

---

## Implementation Order

```
Phase 0 — Shared Abstractions (prerequisite)
  0a. toride-service              ← cleanest extraction, near-identical patterns
  0b. toride-fs                   ← unifies 9 atomic_write implementations
  0c. toride-runner               ← shared Runner trait (highest blast radius)
  0d. toride-diagnostic-types     ← just types, trivial migration
  0e. Migrate existing crates     ← delete duplicated code, update imports

Phase 1 — Foundation (P0)
  1. toride-updates               ← most impactful: unpatched systems are #1 breach cause
  2. toride-harden                ← complements existing firewall/fail2ban

Phase 2 — Access Control (P1)
  3. toride-users                 ← least privilege, 2FA, sudo hardening
  4. toride-wireguard             ← VPN for network isolation
  5. toride-audit                 ← auditd + AIDE + log management

Phase 3 — Application Layer (P1)
  6. toride-proxy                 ← reverse proxy + TLS + WAF

Phase 4 — Operations (P2)
  7. toride-backup                ← backup scheduling and restore testing
  8. toride-cloud                 ← cloud provider security groups
  9. toride-monitor               ← outbound/exfiltration monitoring
  10. toride-tailscale            ← managed mesh VPN (API-driven)
```

---

## Dependency Graph

```
                         toride (binary)
                             │
        ┌────────────────────┼───────────────────────┐
        │                    │                       │
   toride-ssh           toride-status          [future deps]
   (existing)           (existing)                   │
        │                                        ┌───┼───────────────────┐
        │                                        │   │                   │
   ┌────┴──────┐                                 ▼   ▼                   ▼
   │ 9 sub-    │                          toride-updates  toride-harden  toride-users
   │ crates    │                                               │      │
   └───────────┘                                          ┌────┘  ┌───┘
                                                          │       │
                                                          ▼       ▼
                                                     toride-audit  toride-proxy
                                                                     │
                                                  ┌──────────────────┼──────────────┐
                                                  ▼                  ▼              ▼
                                             toride-backup    toride-cloud   toride-monitor
                                                                                  │
                                                                                  ▼
                                                                             toride-tailscale

  ═══════════════════════════════════════════════════════════════════════════
  Shared foundation — every new crate depends on these:

  toride-runner ────── toride-service
       │
       ├────────────── toride-fs
       │
       └────────────── toride-diagnostic-types

  Existing (unchanged):
  toride-fail2ban ─── (will migrate to shared crates later)
  ufw-kit ─────────── (will migrate to shared crates later)
```

### Cross-Crate Integration Points (Optional)

These are runtime or optional-dep relationships, not compile-time:

| From | To | Purpose |
|------|----|---------|
| `toride-users` | `toride-ssh` | sshd_config hardening directives |
| `toride-monitor` | `ufw-kit` | iptables OUTPUT chain logging |
| `toride-cloud` | `ufw-kit` | firewall rule reconciliation |
| `toride-backup` | `toride-proxy` | TLS cert backup |
| `toride-wireguard` | `ufw-kit` | VPN interface in firewall rules |
| `toride-audit` | `toride-harden` | sysctl change monitoring |

---

## Full Workspace Structure

```
toride/
├── Cargo.toml                              # workspace root (members = ["crates/*", "crates/toride-ssh/crates/*"])
│
├── crates/
│   │  ──── SHARED FOUNDATION (new) ────────────────────────────────
│   ├── toride-runner/                      # Runner trait, CommandSpec, DuctRunner, FakeRunner, redaction
│   │   └── src/{lib,runner,spec,output,fake,redact,discovery}.rs
│   ├── toride-fs/                          # atomic_write, file locking, path expansion, permissions
│   │   └── src/{lib,atomic,lock,permissions,expand,read}.rs
│   ├── toride-diagnostic-types/            # Severity, Finding, check helpers
│   │   └── src/{lib,severity,finding,helpers}.rs
│   ├── toride-service/                     # systemd service management
│   │   └── src/{lib,manager,free_functions,error}.rs
│   │
│   │  ──── EXISTING CRATES ────────────────────────────────────────
│   ├── toride/                             # Binary: TUI app
│   ├── toride-ssh/                         # Umbrella: SSH management
│   │   └── crates/{core,config,key,agent,authorized-keys,known-hosts,doctor,certificate,forward}/
│   ├── toride-status/                      # System metrics
│   ├── toride-fail2ban/                    # Fail2Ban management
│   ├── ufw-kit/                            # UFW firewall
│   └── ufw-kit-test-support/              # Test utilities
│   │
│   │  ──── NEW VPS SECURITY CRATES ────────────────────────────────
│   ├── toride-updates/                     # P0: Auto security updates
│   │   └── src/{lib,error,paths,spec,report,client,service,doctor,config,
│   │            backup,detect,apt,dnf,schedule,cli}.rs
│   ├── toride-harden/                      # P0: Kernel hardening (sysctl)
│   │   └── src/{lib,error,paths,spec,report,client,doctor,config,
│   │            backup,profile,sysctl,shm,cli}.rs
│   ├── toride-users/                       # P1: User/sudo/PAM/2FA
│   │   └── src/{lib,error,paths,spec,report,client,doctor,config,
│   │            backup,user,sudo,pam,totp,password,cli}.rs
│   ├── toride-wireguard/                   # P1: WireGuard VPN
│   │   └── src/{lib,error,paths,spec,report,client,service,doctor,config,
│   │            backup,net,peer,cli}.rs
│   ├── toride-audit/                       # P1: auditd + AIDE + logs (features: auditd, integrity, logs, ids)
│   │   └── src/{lib,error,paths,spec,report,client,doctor,backup,
│   │            auditd,auditd_config,auditd_rules,auditd_parse,auditd_presets,
│   │            integrity,integrity_config,integrity_parse,
│   │            logs,logs_rsyslog,logs_journald,logs_rotation,
│   │            ids}.rs
│   ├── toride-proxy/                       # P1: Reverse proxy + TLS (features: nginx, caddy, certs, waf)
│   │   └── src/{lib,error,paths,spec,report,client,service,doctor,backup,
│   │            nginx,nginx_config,nginx_headers,caddy,
│   │            certs,certs_parse,certs_renewal,waf,cli}.rs
│   ├── toride-backup/                      # P2: Backup scheduling
│   │   └── src/{lib,error,paths,spec,report,client,service,doctor,config,
│   │            backup,restic,borg,schedule,restore,cli}.rs
│   ├── toride-cloud/                       # P2: Cloud provider security
│   │   └── src/{lib,error,paths,spec,report,client,doctor,detect,
│   │            aws,gcp,digitalocean,hetzner,cli}.rs
│   ├── toride-monitor/                     # P2: Outbound monitoring
│   │   └── src/{lib,error,paths,spec,report,client,doctor,config,
│   │            output,conntrack,anomaly,alert,cli}.rs
│   └── toride-tailscale/                   # P2: Tailscale mesh VPN
│       └── src/{lib,error,paths,spec,report,client,doctor,api,acl,tailnet,dns,cli}.rs
│
├── docs/
│   └── vps-security-crate-split.md         # This document
├── examples/
├── tests/
├── dev/
└── web/
```

**Total: 30 crates** (1 binary, 29 libraries) — up from 16 today.

---

## Convention Reference

Every new crate follows these established patterns extracted from the existing workspace:

### Cargo.toml Template

```toml
[package]
name = "toride-xxx"
version = "0.1.0"
edition = "2024"
description = "One-line description"
license = "MIT"

[features]
default = ["client", "doctor"]
client = ["dep:duct"]
doctor = ["service"]
service = ["client"]
config = ["client", "dep:regex"]
serde = ["dep:serde", "dep:serde_json"]
tokio = ["dep:tokio"]
cli = ["dep:clap"]

[dependencies]
toride-runner = { path = "../toride-runner" }
toride-fs = { path = "../toride-fs" }
toride-diagnostic-types = { path = "../toride-diagnostic-types" }
toride-service = { path = "../toride-service", optional = true }
thiserror = { workspace = true }
tracing = { workspace = true }
which = { workspace = true }
serde = { workspace = true, features = ["derive"], optional = true }
serde_json = { workspace = true, optional = true }
tokio = { workspace = true, optional = true }
clap = { version = "4", features = ["derive"], optional = true }
chrono = { version = "0.4", optional = true }

[dev-dependencies]
insta = "1"
tempfile = "3"
assert_fs = "1"
proptest = "1"

[lints]
workspace = true
```

### Module Layout

Each new crate uses shared crates for cross-cutting concerns and only contains domain logic:

```
toride-xxx/
├── Cargo.toml
└── src/
    ├── lib.rs           # Crate root, module declarations, re-exports
    ├── error.rs         # #[non_exhaustive] Error enum + Result<T> (domain-specific only)
    ├── paths.rs         # XxxPaths struct (domain-specific paths, uses toride-fs for expansion)
    ├── spec.rs          # Domain types, builders (XxxSpec)
    ├── report.rs        # Status reports, apply reports (uses toride-diagnostic-types::Finding)
    ├── client.rs        # #[cfg(feature = "client")] Main entry struct (uses toride-runner::Runner)
    ├── service.rs       # #[cfg(feature = "service")] (uses toride-service::ServiceManager)
    ├── doctor.rs        # #[cfg(feature = "doctor")] (uses toride-diagnostic-types helpers)
    ├── config.rs        # #[cfg(feature = "config")] Config file parsing (uses toride-fs::atomic_write)
    ├── backup.rs        # Pre-mutation backup (uses toride-fs)
    ├── domain.rs        # Domain-specific modules (apt.rs, sysctl.rs, etc.)
    ├── cli.rs           # #[cfg(feature = "cli")] clap args
    ├── *.test.rs        # Co-located tests via #[path = "module.test.rs"]
    └── snapshots/       # insta snapshot test files
```

**What each new crate gets from shared crates:**

| Concern | Shared Crate | No longer in domain crate |
|---------|-------------|--------------------------|
| Command execution | `toride-runner` | Runner trait, DuctRunner, FakeRunner |
| Sensitive redaction | `toride-runner` | redact_args, REDACT_FLAGS |
| Binary discovery | `toride-runner` | binary_exists, find_binary |
| Atomic writes | `toride-fs` | tempfile + rename boilerplate |
| File locking | `toride-fs` | acquire_lock, fs2 setup |
| Path expansion | `toride-fs` | expand_tilde, expand_path |
| Diagnostic types | `toride-diagnostic-types` | Severity, Finding |
| Binary/perm checks | `toride-diagnostic-types` | check_binary_exists, check_file_permissions |
| Service management | `toride-service` | systemctl wrapper boilerplate |

### Security Model Checklist

Every crate MUST implement:

- [ ] **No shell injection** — args as arrays, never concatenated strings
- [ ] **Sensitive value redaction** — `REDACT_FLAGS` for passwords/tokens/keys
- [ ] **Path traversal prevention** — reject `..`, `/`, newlines in names
- [ ] **World-writable detection** — doctor checks `o+w` bits on config dirs
- [ ] **File ownership validation** — config files must be root-owned
- [ ] **Dry-run mode** — all destructive operations previewable
- [ ] **Advisory locking** — `fd-lock` for concurrent write coordination
- [ ] **Atomic writes** — tempfile + rename for all config mutations
- [ ] **`#![deny(unsafe_code)]`** — enforced at crate root

### Domain-Specific Security Concerns

Beyond the generic checklist, each crate has domain-specific risks:

| Crate | Domain-Specific Risk | Mitigation |
|-------|---------------------|------------|
| `toride-users` | PAM/secret file reads (shadow) | Never read `/etc/shadow`; delegate to `passwd`/`usermod` |
| `toride-users` | TOTP secret storage | Warn if `.google_authenticator` is world-readable |
| `toride-proxy` | Private keys in memory | Zeroize key material after cert operations; warn on key exposure |
| `toride-backup` | Encryption passwords in env vars | Doctor warns on `RESTIC_PASSWORD` in shell history |
| `toride-wireguard` | Private keys in config files | Doctor checks permissions on `/etc/wireguard/*.conf` (must be 0600) |
| `toride-monitor` | Log volume DoS | Rate-limit iptables LOG target; warn on excessive logging |
| `toride-cloud` | Provider credential exposure | Redact all `AWS_*`, `GOOGLE_*`, `DIGITALOCEAN_*` env vars in logs |

---

## Appendix: Per-Crate Details

### 1. `toride-updates` — Automatic Security Updates

**Priority:** P0 | **Complexity:** Medium | **Modules:** ~16

Manages automatic security updates on Linux VPS hosts. Wraps `unattended-upgrades` on Debian/Ubuntu and `dnf-automatic` on Fedora/RHEL.

**Wraps:** `unattended-upgrades`, `apt-get`, `dnf-automatic`, `systemctl`, `crontab`

**Features:**
| Feature | Description |
|---------|-------------|
| `client` | CLI tool wrapper, DuctRunner, service management |
| `doctor` | Verifies auto-updates active, schedules configured |
| `config` | APT conf and dnf-automatic.conf parsing/writing |
| `apt` | Debian/Ubuntu backend |
| `dnf` | Fedora/RHEL backend |
| `schedule` | Systemd timer / cron schedule management |
| `cli` | clap argument parsing |
| `serde` | Serialization for specs and reports |

**Doctor Checks:**
- `binary.unattended-upgrades.missing` — tool not installed
- `service.unattended-upgrades.inactive` — service not running
- `config.auto-updates.disabled` — auto-updates turned off
- `config.schedule.missing` — no update schedule configured
- `schedule.stale-last-run` — updates haven't run in >7 days
- `permission.config-dir-world-writable` — insecure permissions

**Integration Points:**
- `toride-status`: reads package manager type and last-update timestamp
- `ufw-kit`: cross-checks update traffic (80/443) is allowed

---

### 2. `toride-harden` — System Hardening

**Priority:** P0 | **Complexity:** Medium | **Modules:** ~14

System hardening via sysctl kernel parameters, shared memory mount restrictions, and kernel security profile management. Applies and audits recommended hardening presets against CIS/STIG benchmarks.

**Wraps:** `sysctl`, `mount`, `findmnt`

**Features:**
| Feature | Description |
|---------|-------------|
| `client` | sysctl CLI wrapper, parameter read/write |
| `doctor` | Audits current sysctl values against hardening profiles |
| `config` | sysctl.d drop-in file parsing and writing |
| `profile` | CIS/STIG hardening preset profiles |

**Doctor Checks (key sysctl params):**
- `kernel.aslr.disabled` — `kernel.randomize_va_space != 2`
- `kernel.dmesg.restrict` — `kernel.dmesg_restrict != 1`
- `kernel.kptr-restrict.disabled` — `kernel.kptr_restrict != 2`
- `net.ipv4.ip-forward.enabled` — forwarding on when not router
- `net.ipv4.conf.all.accept-redirects.enabled` — accepts ICMP redirects
- `shm.dev-shm.noexec.missing` — `/dev/shm` mounted with exec
- `fs.protected-hardlinks.disabled` — hardlink protection off
- `fs.protected-symlinks.disabled` — symlink protection off

**Hardening Profiles:** Desktop, Server, Router (each enables different sysctl params)

---

### 3. `toride-users` — User & Access Control

**Priority:** P1 | **Complexity:** Medium | **Modules:** ~16

OS-level user and access control management: user creation with least privilege, sudoers configuration, PAM/2FA/TOTP enrollment, and password policy enforcement.

**Wraps:** `useradd`, `usermod`, `userdel`, `passwd`, `visudo`, `pam-auth-update`, `google-authenticator`

**Features:**
| Feature | Description |
|---------|-------------|
| `client` | CLI tool wrapper for user/group management |
| `doctor` | Audits user accounts, sudo config, PAM, 2FA status |
| `config` | sudoers, PAM config, password policy parsing/writing |
| `totp` | google-authenticator / pam-oath TOTP enrollment |

**Doctor Checks:**
- `user.root.login-enabled` — root has login capability
- `user.empty-password` — accounts with no password set
- `sudo.nopasswd.entries` — `NOPASSWD` in sudoers
- `pam.totp.not-configured` — no 2FA for SSH
- `password.max-days.excessive` — password expiry > 90 days
- `permission.sudoers-d-world-writable` — insecure sudoers permissions

**Integration Points:**
- `toride-ssh`: cross-references `sshd_config` `PasswordAuthentication` and `PermitRootLogin`
- `toride-harden`: cross-references `kernel.yama.ptrace_scope` for process isolation

---

### 4. `toride-wireguard` — WireGuard VPN

**Priority:** P1 | **Complexity:** Medium | **Modules:** ~12

WireGuard tunnel management: interface configs (wg-quick INI format), peer lifecycle, key generation, and tunnel health monitoring.

**Wraps:** `wg`, `wg-quick`, `ip`

**Features:**
| Feature | Description |
|---------|-------------|
| `client` | wg/wg-quick CLI wrapper |
| `doctor` | Tunnel active, peer connectivity, DNS leak check |
| `config` | INI config parsing/writing for wg-quick.conf |
| `peer` | Peer addition, removal, key rotation |

**Doctor Checks:**
- `binary.wg.missing` — WireGuard tools not installed
- `service.wireguard.inactive` — tunnel not running
- `tunnel.handshake.stale` — no recent handshake (peer unreachable)
- `tunnel.dns.leak` — DNS queries bypass VPN
- `secrets.private-key-in-config` — private key in world-readable file
- `permission.wireguard-config-world-readable` — config not 0600

---

### 5. `toride-audit` — Audit & Integrity

**Priority:** P1 | **Complexity:** Medium-Large | **Modules:** ~20

Single crate with feature gates covering Linux audit daemon, file integrity monitoring, log aggregation, and IDS integration.

**Wraps:** `auditctl`, `auditd`, `aureport`, `ausearch`, `aide`, `rsyslogd`, `journalctl`, `logrotate`

**Features:**
| Feature | Description |
|---------|-------------|
| `auditd` | Audit daemon management, rule presets, report parsing |
| `integrity` | AIDE database management, scheduled checks, config |
| `logs` | rsyslog, journald, logrotate management |
| `ids` | Wazuh/OSSEC integration (future, P2) |
| `presets` | CIS/STIG audit rule templates |

**Doctor Checks:**
- `binary.auditctl.missing` — audit tools not installed
- `service.auditd.inactive` — audit daemon not running
- `config.rules.cis-incomplete` — missing CIS benchmark rules
- `aide.database.stale` — AIDE database not recently updated
- `aide.database.missing` — no AIDE database initialized
- `log.rotation.misconfigured` — log rotation not set up
- `log.rsyslog.not-forwarding` — no central log shipping

---

### 6. `toride-proxy` — Reverse Proxy & TLS

**Priority:** P1 | **Complexity:** Large | **Modules:** ~18

Single crate with feature gates for reverse proxy configuration, TLS certificate lifecycle, and WAF rule management.

**Wraps:** `nginx`, `caddy`, `certbot`, `acme.sh`, `openssl`

**Features:**
| Feature | Description |
|---------|-------------|
| `nginx` | Nginx server block management, security headers |
| `caddy` | Caddyfile management, auto-TLS |
| `certs` | certbot/acme.sh lifecycle, expiry monitoring |
| `waf` | ModSecurity/Coraza rule management (future, P2) |

**Doctor Checks:**
- `binary.nginx.missing` / `binary.caddy.missing` — no proxy installed
- `service.nginx.inactive` — proxy not running
- `config.security-headers.missing` — HSTS, X-Frame-Options, CSP not set
- `cert.expiry.imminent` — certificate expires within 14 days
- `cert.expiry.expired` — certificate has expired
- `cert.renewal.not-configured` — no auto-renewal timer
- `config.nginx.syntax-error` — `nginx -t` failed

---

### 7. `toride-backup` — Backup & Recovery

**Priority:** P2 | **Complexity:** Large | **Modules:** ~15

Backup scheduling, repository management, restore testing, and integrity verification via restic or borg.

**Wraps:** `restic`, `borg`, `systemctl` (timers), `crontab`

**Features:**
| Feature | Description |
|---------|-------------|
| `client` | restic/borg CLI wrapper |
| `doctor` | Backup health, freshness, integrity checks |
| `config` | Repository config, retention policies |
| `schedule` | Cron/systemd timer scheduling |
| `restore` | Restore workflows and verification |

**Doctor Checks:**
- `binary.restic.missing` — no backup tool installed
- `backup.last-run.stale` — no backup in >48 hours
- `backup.integrity.failed` — `restic check` found errors
- `backup.repository.inaccessible` — can't reach storage backend
- `backup.retention.missing` — no retention policy configured
- `backup.encryption.disabled` — repository not encrypted

---

### 8. `toride-cloud` — Cloud Provider Security

**Priority:** P2 | **Complexity:** Medium | **Modules:** ~12

Cloud provider detection and security group management. Wraps provider CLIs for firewall rules, disk encryption, and IP allowlisting.

**Wraps:** `aws` (CLI v2), `gcloud`, `doctl`, `hcloud`

**Features:**
| Feature | Description |
|---------|-------------|
| `client` | Provider CLI wrapper |
| `detect` | Auto-detect cloud provider via metadata endpoint |
| `firewall` | Security group / cloud firewall management |
| `aws` | AWS EC2 security groups |
| `gcp` | GCP firewall rules |
| `digitalocean` | DO firewall management |
| `hetzner` | Hetzner firewall management |

---

### 9. `toride-monitor` — Outbound Monitoring

**Priority:** P2 | **Complexity:** Medium | **Modules:** ~14

Outbound traffic monitoring and anomaly detection. Configures iptables/nftables OUTPUT chain logging, parses conntrack data, and alerts on suspicious outbound connections.

**Wraps:** `iptables`, `nftables`, `conntrack`, `ss`

**Features:**
| Feature | Description |
|---------|-------------|
| `client` | iptables/nft CLI wrapper |
| `doctor` | Logging rules active, no excessive log volume |
| `config` | Logging rule configuration, anomaly thresholds |
| `detect` | Anomaly detection heuristics |
| `alert` | Alert dispatching (journald, webhook) |

**Doctor Checks:**
- `logging.output-chain.disabled` — no outbound logging
- `logging.volume.excessive` — LOG rules generating too much data
- `analyzer.conntrack.missing` — conntrack tool not available
- `alert.destination.missing` — no alert endpoint configured

---

### 10. `toride-tailscale` — Tailscale Mesh VPN

**Priority:** P2 | **Complexity:** Medium | **Modules:** ~12

Tailscale managed mesh VPN integration via its HTTP API. Requires async runtime (tokio + reqwest).

**Wraps:** `tailscale` CLI, Tailscale HTTP API

**Features:**
| Feature | Description |
|---------|-------------|
| `client` | Tailscale CLI + HTTP API wrapper |
| `doctor` | Node connected, ACL active, DNS configured |
| `acl` | ACL policy management via API |
| `tailnet` | Network topology inspection |

**Why separate from WireGuard:** Tailscale requires `tokio` + `reqwest` for its HTTP API. WireGuard is purely sync config-file management. Combining them would force async dependencies on users who only need WireGuard.

---

## Summary

| Phase | Crates | Modules |
|-------|--------|---------|
| Phase 0 (Shared) | `toride-runner`, `toride-fs`, `toride-diagnostic-types`, `toride-service` | ~20 |
| Phase 1 (P0) | `toride-updates`, `toride-harden` | ~30 |
| Phase 2 (P1) | `toride-users`, `toride-wireguard`, `toride-audit` | ~48 |
| Phase 3 (P1) | `toride-proxy` | ~18 |
| Phase 4 (P2) | `toride-backup`, `toride-cloud`, `toride-monitor`, `toride-tailscale` | ~53 |
| **Total** | **14 new crates** | **~169 modules** |

The workspace grows from 16 to 30 crates. Phase 0 extracts ~950 lines of duplicated code from existing crates into 4 shared libraries, eliminating 3 Runner traits, 9 atomic_write implementations, and scattered Severity/Finding definitions. Every subsequent crate is built on this proven shared foundation.

