# Product Goal

Build a Rust + Ratatui terminal application that guides a user through VPS setup, security hardening, developer tooling installation, deployment stack installation, and quality-of-life configuration.

The app should not be a random shell-script runner. It should feel like a guided installer with profiles, checklists, warnings, dependency handling, dry-runs, logs, rollback notes, and reusable recipes.

The core idea:

> Select a profile → review modules → configure options → run preflight checks → apply setup → show summary, logs, next steps, and generated restore/debug commands.

---

# Target Users

## Primary users

* Developers setting up fresh VPS servers
* Indie hackers deploying apps
* Agencies preparing client servers
* Homelab users
* AI-agent users who want repeatable server environments
* People deploying Dokploy, Coolify, Traefik, Caddy, Docker, Node, Bun, Rust, Go, and similar stacks

## Supported VPS environments

Initial target:

* Debian 12
* Ubuntu 22.04 LTS
* Ubuntu 24.04 LTS

Later:

* Debian 13
* AlmaLinux / Rocky Linux
* Fedora Server
* Arch-based servers only as experimental

---

# Core Profiles

## 1. Basic Profile

For a normal production VPS.

Preselected modules:

* System update
* Create non-root sudo user
* Add SSH key
* Disable root SSH login
* Disable password SSH login after key verification
* UFW firewall
* Fail2Ban
* Docker
* Docker Compose plugin
* Swap
* Basic system utilities
* Timezone / locale setup
* Unattended security upgrades
* Basic monitoring tools

Optional:

* Node/NVM
* Bun
* Rust
* Go
* Python tooling
* Tailscale
* Caddy or Traefik

## 2. Sandbox Profile

For testing, experiments, temporary VPS instances, AI-agent playgrounds, or unsafe prototypes.

Preselected modules:

* System update
* Create non-root sudo user
* SSH key setup
* UFW firewall
* Docker
* Docker Compose plugin
* Node/NVM
* Bun
* Deno
* Rust
* Go
* Python tooling
* Tailscale
* Swap
* Dev utilities

Less strict by default:

* Root login can remain enabled until the user confirms key-based access works
* Password login can remain temporarily enabled
* Cloudflare-only HTTP/S disabled by default
* Fail2Ban optional

## 3. Custom Profile

User manually selects everything.

The app should still warn about unsafe combinations, missing dependencies, and conflicting choices.

Examples:

* Dokploy requires Docker
* Coolify requires Docker
* Docker-based Traefik should require Docker
* Cloudflare-only HTTP/S requires the user to confirm they actually use Cloudflare proxy
* Disabling password SSH login requires SSH key validation first

---

# Main Menu Structure

```text
VPS Setup
├─ Profiles
│  ├─ Basic
│  ├─ Sandbox
│  └─ Custom
│
├─ System Basics
│  ├─ System update / upgrade
│  ├─ Hostname
│  ├─ Timezone
│  ├─ Locale
│  ├─ Swap
│  ├─ Essential packages
│  └─ Reboot check
│
├─ Users & SSH
│  ├─ Create sudo user
│  ├─ Add SSH key
│  ├─ Disable root login
│  ├─ Disable password login
│  ├─ Change SSH port
│  ├─ SSH config validation
│  └─ Emergency rollback instructions
│
├─ Firewall & Security
│  ├─ UFW
│  ├─ Fail2Ban
│  ├─ Cloudflare-only HTTP/S
│  ├─ Rate limiting
│  ├─ Automatic security updates
│  ├─ Kernel hardening sysctl
│  └─ Audit tools
│
├─ Developer Runtimes
│  ├─ Node.js
│  ├─ NVM
│  ├─ Bun
│  ├─ Deno
│  ├─ Rust
│  ├─ Go
│  ├─ Python
│  └─ Java / JDK optional
│
├─ Containers
│  ├─ Docker
│  ├─ Docker Compose plugin
│  ├─ Docker user permissions
│  ├─ Docker log rotation
│  └─ Docker daemon config
│  └─ Docker daemon config

├─ Server Managers
│  ├─ Dokploy
│  ├─ Coolify
│  └─ None
│
├─ Reverse Proxy
│  ├─ Caddy native
│  ├─ NGINX native
│  ├─ Traefik native
│  ├─ Caddy in Docker
│  ├─ NGINX in Docker
│  ├─ Traefik in Docker
│  └─ Let server manager handle it
│
├─ Networking
│  ├─ Tailscale
│  ├─ Cloudflare Tunnel
│  ├─ WireGuard optional
│  └─ DNS helpers
│
├─ Quality of Life
│  ├─ zsh / fish optional
│  ├─ starship prompt optional
│  ├─ tmux
│  ├─ htop / btop
│  ├─ ncdu
│  ├─ jq
│  ├─ ripgrep
│  ├─ fd
│  ├─ git
│  ├─ curl / wget
│  └─ log viewer helpers
│
├─ Observability
│  ├─ Node exporter
│  ├─ Prometheus optional
│  ├─ Grafana optional
│  ├─ Netdata optional
│  ├─ Uptime Kuma optional
│  └─ Log rotation
│
└─ Run Plan
   ├─ Preflight check
   ├─ Dry run
   ├─ Apply
   ├─ Save logs
   └─ Export setup report
```

---

# Service Selection List

Base checklist:

```text
[ ] Docker
[ ] Node.js
[ ] NVM
[ ] Bun
[ ] Deno
[ ] Rust
[ ] Go
[ ] Python
[ ] UFW
[ ] Fail2Ban
[ ] Cloudflare-only HTTP/S
[ ] SSH hardening
[ ] Swap
[ ] Dokploy
[ ] Coolify
[ ] Traefik
[ ] Caddy
[ ] NGINX
[ ] Tailscale
[ ] Cloudflare Tunnel
[ ] Automatic security updates
[ ] Docker log rotation
[ ] Basic monitoring tools
[ ] Backup tools
```

---

# Important Service Grouping

## JavaScript runtimes

Options:

* Node.js from system package manager
* Node.js from NodeSource
* NVM-managed Node.js
* Bun
* Deno

Recommended UX:

```text
JavaScript Runtime
[x] Node.js
[ ] NVM
[x] Bun
[ ] Deno

Node install method:
( ) OS package
( ) NodeSource
(*) NVM
```

Important rule:

* Do not install both system Node and NVM Node without warning.
* If Bun is selected, still ask whether Node compatibility is needed.
* If NVM is selected for a non-root user, install it under that user, not root.

## Server managers

Options:

* Dokploy
* Coolify
* None

Rules:

* Dokploy requires Docker.
* Coolify requires Docker.
* Do not install both by default.
* If one is selected, ask whether the reverse proxy should be managed by the server manager.

## Reverse proxy

Options:

* Caddy
* NGINX
* Traefik
* Docker-based Caddy
* Docker-based NGINX
* Docker-based Traefik
* Handled by Dokploy/Coolify

UX rule:

If Docker is selected, ask:

```text
Docker is enabled. How should reverse proxy be installed?

( ) Native system package
( ) Docker container
( ) Let Dokploy/Coolify manage it
( ) Skip reverse proxy
```

Conflict warnings:

* Avoid binding multiple services to ports 80 and 443.
* Warn if Dokploy/Coolify and standalone Traefik/Caddy are both selected.
* Warn if Cloudflare-only HTTP/S is enabled but the user does not use proxied Cloudflare DNS.

---

# Extra Essential VPS Modules

These are the useful things people commonly need beyond runtime installation.

## Security essentials

* Automatic security updates
* UFW firewall
* Fail2Ban
* SSH hardening
* Disable root SSH login
* Disable password SSH login
* SSH key install and validation
* Optional SSH port change
* Cloudflare-only HTTP/S firewall rules
* Docker daemon hardening
* System audit summary
* Reboot-required detection
* Basic sysctl hardening
* Login history summary
* Open ports summary

## Quality-of-life essentials

* git
* curl
* wget
* unzip
* tar
* jq
* ripgrep
* fd-find
* nano / vim / neovim
* tmux
* htop / btop
* ncdu
* lsof
* net-tools or modern alternatives
* dnsutils
* ca-certificates
* gnupg
* build-essential
* pkg-config

## Reliability essentials

* Swap file creation
* Docker log rotation
* journald log limits
* unattended-upgrades
* time sync
* disk usage warnings
* memory check
* reboot-required check
* service status report

## Backup essentials

* Restic
* BorgBackup
* Rclone
* Database dump helpers
* Docker volume backup helper
* Cron/systemd timer setup
* Backup restore instructions

## Monitoring essentials

* Uptime Kuma
* Netdata
* Prometheus node_exporter
* Grafana optional
* Docker container health summary
* Disk usage summary
* Failed services summary

## Networking essentials

* Tailscale
* Cloudflare Tunnel
* WireGuard optional
* DNS check tools
* Public IP detection
* IPv6 detection
* Open port testing
* Firewall rule summary

---

# Security Flow

Security must be done carefully to avoid locking the user out.

## Safe SSH hardening flow

1. Detect current SSH connection.
2. Detect current user.
3. Ask for new username.
4. Create user.
5. Add user to sudo group.
6. Add SSH public key.
7. Validate authorized_keys permissions.
8. Test whether the new user can log in.
9. Only then offer to disable root login.
10. Only then offer to disable password login.
11. Validate sshd config using `sshd -t` before restart.
12. Restart SSH safely.
13. Show emergency rollback command.

The app should never blindly disable root/password login before verifying key access.

---

# Cloudflare-only HTTP/S Flow

This feature should restrict ports 80 and 443 to Cloudflare IP ranges only.

UX:

```text
Cloudflare-only HTTP/S protects your origin server by allowing only Cloudflare IP ranges to reach ports 80/443.

Use this only if your domain is proxied through Cloudflare.

Enable?
[ ] Yes
[ ] No
```

Implementation notes:

* Fetch Cloudflare IPv4 and IPv6 ranges.
* Store a local copy.
* Apply UFW rules for 80/443 from those ranges.
* Deny other HTTP/S traffic.
* Add update command to refresh Cloudflare ranges.
* Add systemd timer option to refresh ranges.

Important warning:

If the user does not use Cloudflare proxied DNS, their website may become unreachable.

Future support:

* Bunny CDN IP allowlist
* Fastly IP allowlist
* CloudFront IP allowlist
* Custom CDN IP allowlist

---

# Architecture

## Rust crates

Suggested stack:

* `ratatui` for TUI
* `crossterm` for terminal backend
* `tokio` for async process handling
* `clap` for CLI flags
* `serde` / `serde_json` / `toml` for config
* `anyhow` or `eyre` for app-level errors
* `thiserror` for typed errors
* `tracing` for logs
* `tracing-subscriber` for log formatting
* `reqwest` for downloading install scripts / IP ranges
* `which` for binary detection
* `nix` for Unix helpers where useful
* `dirs` for config paths

## Internal modules

```text
src/
├─ main.rs
├─ app.rs
├─ tui/
│  ├─ mod.rs
│  ├─ screens.rs
│  ├─ widgets.rs
│  └─ theme.rs
├─ profiles/
│  ├─ mod.rs
│  ├─ basic.rs
│  ├─ sandbox.rs
│  └─ custom.rs
├─ modules/
│  ├─ mod.rs
│  ├─ docker.rs
│  ├─ node.rs
│  ├─ bun.rs
│  ├─ deno.rs
│  ├─ rust.rs
│  ├─ go.rs
│  ├─ python.rs
│  ├─ ssh.rs
│  ├─ ufw.rs
│  ├─ fail2ban.rs
│  ├─ cloudflare.rs
│  ├─ swap.rs
│  ├─ dokploy.rs
│  ├─ coolify.rs
│  ├─ caddy.rs
│  ├─ nginx.rs
│  ├─ traefik.rs
│  └─ tailscale.rs
├─ executor/
│  ├─ mod.rs
│  ├─ command.rs
│  ├─ plan.rs
│  ├─ dry_run.rs
│  └─ logs.rs
├─ system/
│  ├─ os_detect.rs
│  ├─ package_manager.rs
│  ├─ users.rs
│  ├─ services.rs
│  └─ ports.rs
└─ config/
   ├─ mod.rs
   └─ schema.rs
```

---

# Module Design

Every installable item should be a module with the same lifecycle.

```rust
trait SetupModule {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn dependencies(&self) -> Vec<&'static str>;
    fn conflicts(&self) -> Vec<&'static str>;
    fn preflight(&self, ctx: &Context) -> Result<PreflightResult>;
    fn plan(&self, ctx: &Context) -> Result<Vec<Action>>;
    fn apply(&self, ctx: &Context) -> Result<()>;
    fn verify(&self, ctx: &Context) -> Result<VerifyResult>;
}
```

The app should generate a plan before applying anything.

Example:

```text
Plan:
1. Update apt package index
2. Install ca-certificates, curl, gnupg
3. Add Docker official repository
4. Install Docker Engine
5. Enable Docker service
6. Add user `deploy` to docker group
7. Configure Docker log rotation
8. Verify `docker version`
```

---

# Execution Modes

## Interactive TUI mode

Default:

```bash
toride
```

## Non-interactive mode

For automation and AI agents:

```bash
toride apply --profile basic --user deploy --ssh-key ~/.ssh/id_ed25519.pub
```

## Dry-run mode

```bash
toride plan --profile basic
```

## Export plan

```bash
toride plan --profile basic --export setup-plan.json
```

## Apply from config

```bash
toride apply --config toride.toml
```

---

# Config File Example

```toml
profile = "basic"

[user]
name = "deploy"
ssh_key_path = "~/.ssh/id_ed25519.pub"
passwordless_sudo = true

[security]
disable_root_login = true
disable_password_login = true
ufw = true
fail2ban = true
cloudflare_only_http = false
auto_security_updates = true

[runtimes]
node = true
node_method = "nvm"
bun = true
deno = false
rust = true
go = true
python = true

[containers]
docker = true
docker_log_rotation = true

[server_manager]
manager = "dokploy"

[reverse_proxy]
mode = "managed_by_server_manager"

[networking]
tailscale = false
cloudflare_tunnel = false

[swap]
enabled = true
size = "2G"
```

---

# TUI Screens

## 1. Welcome

Show:

* App name
* Detected OS
* Current user
* Root/non-root status
* Public IP
* Memory
* Disk
* Existing Docker/Node/etc detection

## 2. Profile Selection

```text
Choose setup profile:

> Basic       Secure production-ready VPS setup
  Sandbox     Developer playground with common runtimes
  Custom      Manually choose every module
```

## 3. Module Selection

Checklist with categories and search/filter.

Controls:

```text
Space: toggle
Enter: configure
/: search
Tab: next category
r: reset profile defaults
p: preview plan
q: quit
```

## 4. Configuration Forms

Examples:

* Username
* SSH public key
* Swap size
* Node install method
* Reverse proxy mode
* Server manager choice
* Cloudflare-only HTTP/S confirmation

## 5. Preflight

Show warnings before applying:

```text
Warnings:
- Password SSH login will be disabled after key validation.
- Dokploy requires Docker. Docker has been added automatically.
- Port 80 is already in use by nginx.
- Cloudflare-only HTTP/S can break direct origin access.
```

## 6. Apply

Show live logs:

```text
[RUNNING] Installing Docker
[DONE] Docker installed
[RUNNING] Configuring UFW
[FAILED] Failed to enable UFW
```

## 7. Summary

Show:

* Installed modules
* Failed modules
* Log file path
* Open ports
* Enabled services
* Next commands
* Reboot recommendation

---

# Idempotency Rules

The app should be safe to run multiple times.

Each module should:

* Detect whether it is already installed
* Skip completed steps
* Repair partial installs where reasonable
* Avoid overwriting config without backup
* Create timestamped backups before modifying system files
* Show diffs for critical config changes

Critical files to backup before edit:

* `/etc/ssh/sshd_config`
* `/etc/ufw/*`
* `/etc/fail2ban/*`
* `/etc/docker/daemon.json`
* reverse proxy configs
* systemd unit files created by the app

---

# Logging

Log locations:

```text
/var/log/toride/setup.log
/var/log/toride/actions.jsonl
/var/log/toride/report.json
```

For non-root local dry-runs:

```text
~/.local/state/toride/logs/
```

Logs should include:

* Timestamp
* Module name
* Command executed
* Exit code
* stdout/stderr summary
* Duration
* Whether the command changed the system

---

# Safety Rules

Hard rules:

1. Never disable SSH password login before confirming key login.
2. Never disable root login before a sudo user exists and works.
3. Never enable UFW without allowing the active SSH port.
4. Never install conflicting reverse proxies without warning.
5. Never overwrite critical config without backup.
6. Never run remote install scripts silently without showing source and command.
7. Never assume Cloudflare-only mode is safe.
8. Never run destructive cleanup commands without explicit confirmation.

---

# MVP Scope

## MVP v0.1

* Ratatui interface
* Profile selection
* Basic profile
* Custom checklist
* OS detection
* System update
* Create user
* Add SSH key
* SSH hardening with validation
* UFW
* Fail2Ban
* Docker
* Docker Compose plugin
* Swap
* Node via NVM
* Bun
* Rust
* Go
* Python basics
* Tailscale
* Dry-run mode
* Logs

## v0.2

* Dokploy installer
* Coolify installer
* Caddy installer
* Traefik installer
* NGINX installer
* Docker reverse proxy mode
* Cloudflare-only HTTP/S
* Docker log rotation
* Unattended upgrades
* Export/import config

## v0.3

* Cloudflare Tunnel
* Backup modules
* Restic/Borg/Rclone
* Monitoring modules
* Uptime Kuma
* Netdata
* Node exporter
* AI-agent friendly JSON output
* Remote execution over SSH

## v0.4

* Plugin system
* Multiple OS families
* Team presets
* Signed recipes
* Web dashboard optional
* Server inventory mode