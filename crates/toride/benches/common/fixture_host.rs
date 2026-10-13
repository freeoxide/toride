//! Deterministic fixture host for the collector benches: a stub-only `PATH`
//! that counts every spawned subprocess, plus a fixture `HOME` and XDG tree.
//!
//! The stubs are shell scripts that append their basename to a counter file
//! before exiting, so the benches can report exact subprocess counts per
//! refresh tick or per collector cycle. Binaries not present in the stub dir
//! resolve to "not installed" for every probe, which keeps both the counts
//! and the degraded bundles identical on every machine.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

const GENERIC_STUB: &str = concat!(
    "#!/bin/sh\n",
    "printf '%s\\n' \"${0##*/}\" >> \"$TORIDE_BENCH_COUNTER\"\n",
    "exit 0\n",
);

const SYSTEMCTL_STUB: &str = concat!(
    "#!/bin/sh\n",
    "printf '%s\\n' \"${0##*/}\" >> \"$TORIDE_BENCH_COUNTER\"\n",
    "case \"$1\" in\n",
    "  is-active) printf 'active\\n'; exit 0 ;;\n",
    "  is-enabled) printf 'enabled\\n'; exit 0 ;;\n",
    "  show) printf 'ActiveState=active\\n'; exit 0 ;;\n",
    "esac\n",
    "exit 0\n",
);

const FAIL2BAN_CLIENT_STUB: &str = concat!(
    "#!/bin/sh\n",
    "printf '%s\\n' \"${0##*/}\" >> \"$TORIDE_BENCH_COUNTER\"\n",
    "case \"$1\" in\n",
    "  version) printf '1.1.0\\n'; exit 0 ;;\n",
    "  banned) printf '\\n'; exit 0 ;;\n",
    "  status) printf 'Jail list:\\n'; exit 0 ;;\n",
    "esac\n",
    "exit 0\n",
);

const UFW_STUB: &str = concat!(
    "#!/bin/sh\n",
    "printf '%s\\n' \"${0##*/}\" >> \"$TORIDE_BENCH_COUNTER\"\n",
    "case \"$*\" in\n",
    "  *version*) printf 'ufw 0.36.2\\n'; exit 0 ;;\n",
    "  *verbose*)",
    " printf 'Status: active\\nLogging: on (low)\\nDefault: deny (incoming),",
    " allow (outgoing), disabled (routed)\\n'; exit 0 ;;\n",
    "  *status*) printf 'Status: active\\n'; exit 0 ;;\n",
    "esac\n",
    "exit 0\n",
);

const STUB_NAMES: &[&str] = &[
    "aide",
    "apparmor_parser",
    "apt",
    "apt-get",
    "auditctl",
    "ausearch",
    "aureport",
    "borg",
    "certbot",
    "cloud-init",
    "conntrack",
    "curl",
    "dnf",
    "dnf-automatic",
    "docker",
    "dmidecode",
    "fail2ban-client",
    "ffmpeg",
    "git",
    "go",
    "iptables",
    "journalctl",
    "mise",
    "nginx",
    "nft",
    "node",
    "npm",
    "pkexec",
    "podman",
    "python3",
    "restic",
    "rsync",
    "sftp",
    "smartctl",
    "ss",
    "ssh",
    "ssh-add",
    "ssh-keygen",
    "ssh-keyscan",
    "systemctl",
    "tailscale",
    "ufw",
    "unattended-upgrades",
    "unzip",
    "visudo",
    "wg",
    "wg-quick",
];

const SSH_CONFIG_FIXTURE: &str = concat!(
    "Host edge-prod\n",
    "  HostName 203.0.113.10\n",
    "  User root\n",
    "  IdentityFile ~/.ssh/id_ed25519\n",
    "\n",
    "Host db-replica\n",
    "  HostName 203.0.113.20\n",
    "  User deploy\n",
    "  Port 2222\n",
);

const KNOWN_HOSTS_FIXTURE: &str =
    "203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8Qm0kQx9pN2rBench7vJw4uZ1yT0hKqM5sEdRfGh6L toride-bench\n";

const COUNTER_ENV: &str = "TORIDE_BENCH_COUNTER";
const MANAGED_ENV: &[&str] = &["HOME", "PATH", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"];

/// Installed fixture environment. Keeps every temp dir alive and restores the
/// process environment on drop.
pub struct FixtureHost {
    home: tempfile::TempDir,
    cache: tempfile::TempDir,
    config: tempfile::TempDir,
    bin: tempfile::TempDir,
    counter: PathBuf,
    saved_env: Vec<(String, Option<String>)>,
}

impl FixtureHost {
    /// Build the fixture tree, generate the fixture SSH key, then install the
    /// stub `PATH` and fixture environment variables.
    pub fn install() -> Self {
        let home = tempfile::tempdir().expect("fixture home tempdir");
        let cache = tempfile::tempdir().expect("fixture cache tempdir");
        let config = tempfile::tempdir().expect("fixture config tempdir");
        let bin = tempfile::tempdir().expect("fixture bin tempdir");

        let ssh_dir = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).expect("create fixture .ssh");
        std::fs::write(ssh_dir.join("config"), SSH_CONFIG_FIXTURE)
            .expect("write fixture ssh config");
        std::fs::write(ssh_dir.join("known_hosts"), KNOWN_HOSTS_FIXTURE)
            .expect("write fixture known_hosts");
        generate_fixture_key(&ssh_dir);

        let log_dir = cache.path().join("toride");
        std::fs::create_dir_all(&log_dir).expect("create fixture log dir");
        let mut log = String::new();
        for n in 1..=200 {
            use std::fmt::Write as _;
            let _ = writeln!(log, "2026-10-13T10:00:00Z toride bench fixture line {n:03}");
        }
        std::fs::write(log_dir.join("toride.log"), log).expect("write fixture toride log");

        for name in STUB_NAMES {
            let body = match *name {
                "systemctl" => SYSTEMCTL_STUB,
                "fail2ban-client" => FAIL2BAN_CLIENT_STUB,
                "ufw" => UFW_STUB,
                _ => GENERIC_STUB,
            };
            write_stub(bin.path(), name, body);
        }

        let counter = bin.path().join("counter.log");
        std::fs::write(&counter, b"").expect("initialize spawn counter");

        let mut fixture = Self {
            home,
            cache,
            config,
            bin,
            counter: counter.clone(),
            saved_env: Vec::new(),
        };
        fixture.apply_env();
        fixture
    }

    fn apply_env(&mut self) {
        // SAFETY: criterion groups run sequentially on one thread and the
        // tokio runtime does not exist yet; nothing reads the environment
        // concurrently and the values are never mutated again.
        unsafe {
            for key in MANAGED_ENV {
                let prior = std::env::var(key).ok();
                self.saved_env
                    .push(((*key).to_owned(), prior));
            }
            std::env::set_var("HOME", self.home.path());
            std::env::set_var("PATH", self.bin.path());
            std::env::set_var("XDG_CACHE_HOME", self.cache.path());
            std::env::set_var("XDG_CONFIG_HOME", self.config.path());
            std::env::set_var("XDG_DATA_HOME", self.config.path().join("data"));
            std::env::set_var(COUNTER_ENV, &self.counter);
            std::env::remove_var("SSH_AUTH_SOCK");
        }
    }

    /// Total subprocess spawns recorded so far.
    pub fn spawn_count(&self) -> usize {
        std::fs::read_to_string(&self.counter).map_or(0, |content| {
            content.lines().filter(|l| !l.is_empty()).count()
        })
    }

    /// Per-binary spawn breakdown over the whole counter.
    pub fn spawn_breakdown(&self) -> Vec<(String, usize)> {
        let content = std::fs::read_to_string(&self.counter).unwrap_or_default();
        let mut counts: HashMap<String, usize> = HashMap::new();
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            *counts.entry(line.to_owned()).or_insert(0) += 1;
        }
        let mut breakdown: Vec<(String, usize)> = counts.into_iter().collect();
        breakdown.sort();
        breakdown
    }
}

impl Drop for FixtureHost {
    fn drop(&mut self) {
        // SAFETY: single-threaded bench teardown; the runtime is gone.
        unsafe {
            for (key, prior) in self.saved_env.drain(..) {
                match prior {
                    Some(value) => std::env::set_var(&key, value),
                    None => {
                        std::env::remove_var(&key);
                    }
                }
            }
            std::env::remove_var(COUNTER_ENV);
        }
    }
}

fn write_stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap_or_else(|e| panic!("write stub {name}: {e}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("chmod stub {name}: {e}"));
    }
}

fn generate_fixture_key(ssh_dir: &Path) {
    let key = ssh_dir.join("id_ed25519");
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "toride-bench",
            "-f",
            &key.to_string_lossy(),
        ])
        .output()
        .expect("run ssh-keygen for the fixture key");
    assert!(
        status.status.success(),
        "fixture key generation failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}
