My updated verdict: **there is no single Rust crate that manages “all SSH things” correctly**. Build this as a layered SSH manager/doctor around OpenSSH behavior, with Rust crates for parsing and safe file handling.

## Best Rust stack

| Area                                                         | Best choice                             | Why                                                                                                                                                                                                  |
| ------------------------------------------------------------ | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SSH public/private keys, certs, known_hosts, authorized_keys | `ssh-key`                               | Pure Rust, supports OpenSSH public/private keys, certificates, signatures, `authorized_keys`, and `known_hosts`; key generation exists behind `ed25519`, `p256`, `rsa` features. ([Docs.rs][1])      |
| OpenSSH config parsing                                       | `ssh2-config-rs`                        | Pure Rust parser aimed at `russh`, supports `IdentityFile`, `ProxyJump`, `CertificateFile`, algorithms, agent flags, etc., but **does not fully support `Match` patterns or tokens**. ([Docs.rs][2]) |
| Config parser for `ssh2`/libssh2 stack                       | `ssh2-config`                           | Parses OpenSSH-style config and can query host-specific params, but it is older and designed around the `ssh2` crate. ([Docs.rs][3])                                                                 |
| Real SSH execution with exact user behavior                  | `openssh`                               | Wraps the system `ssh` binary, so existing `~/.ssh/config`, agent, ProxyJump, certs, etc. behave like the real CLI. ([Docs.rs][4])                                                                   |
| Pure Rust SSH client/server                                  | `russh`                                 | Use when you want native Rust SSH client/server, agent, key handling, forwarding-style work. Its keys module handles opening key files, encrypted keys, and agents. ([Docs.rs][5])                   |
| libssh2 client                                               | `ssh2`                                  | Rust bindings to libssh2; client-only, SSH protocol v2 only. Useful, but less OpenSSH-compatible than shelling out to `ssh`. ([Docs.rs][6])                                                          |
| SSH agent protocol                                           | `ssh-agent-client-rs` / `ssh-agent-lib` | `ssh-agent-client-rs` is a pure Rust synchronous client; `ssh-agent-lib` is for custom agents and connecting to existing ones. ([Docs.rs][7])                                                        |
| Interactive commands / password prompts                      | `portable-pty`                          | Useful if your app needs to run real `ssh`, `ssh-keygen`, or `ssh-add` interactively in a pseudo-terminal. ([Docs.rs][8])                                                                            |

## What you were missing

You should not only manage private keys. A full SSH manager needs these modules:

### 1. Key inventory

Scan:

```txt
~/.ssh/id_*
~/.ssh/*.pub
~/.ssh/*-cert.pub
custom IdentityFile paths from ~/.ssh/config
agent identities from SSH_AUTH_SOCK
```

Track:

```txt
path
type: ed25519 / rsa / ecdsa / sk-ed25519 / sk-ecdsa
fingerprint sha256
comment
has_public_pair
has_certificate
encrypted/passphrase-protected
permissions
last_modified
used_by_hosts
```

OpenSSH default identity filenames include `id_rsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, and `id_ed25519_sk`. ([OpenBSD Manual Pages][9])

### 2. Create new keys

Support presets:

```txt
ed25519              default modern key
rsa 4096             compatibility
ed25519-sk           hardware/FIDO key
ecdsa-sk             hardware/FIDO compatibility
```

Use either:

```txt
ssh-key crate        for pure Rust generation
ssh-keygen           for exact OpenSSH behavior, FIDO, PKCS#11, certificates
```

Important missing flags/features:

```txt
comment
passphrase
KDF rounds / -a equivalent
output path collision protection
generate .pub from private key
optional add to ssh-agent
optional add Host block to config
optional install to remote authorized_keys
```

`ssh-keygen -y` prints the public key from a private key, and `ssh-keygen` supports KDF rounds, fingerprints, known_hosts search/removal/hash, import/export, FIDO resident keys, KRLs, and certificates. ([OpenBSD Manual Pages][10])

### 3. Remove keys safely

Deleting a key is not just `rm`.

Your delete flow should offer:

```txt
remove private key
remove .pub
remove -cert.pub
remove from ssh-agent
remove IdentityFile references from ~/.ssh/config
optionally remove matching public key from remote authorized_keys
backup before delete
```

Agent removal maps to `ssh-add -d`, and deleting all loaded identities maps to `ssh-add -D`. ([OpenBSD Manual Pages][11])

### 4. Public key generation / repair

Add command:

```txt
ssh-manager key repair-public ~/.ssh/id_ed25519
```

Behavior:

```txt
read private key
derive public key
write ~/.ssh/id_ed25519.pub
preserve or regenerate comment
set permissions
```

This is a must-have because many people lose `.pub` files but still have the private key.

### 5. Multiple key management

You need a proper `Host` profile model:

```sshconfig
Host github-personal
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519_personal
  IdentitiesOnly yes

Host github-work
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519_work
  IdentitiesOnly yes
```

Important: OpenSSH allows multiple `IdentityFile` entries and tries them in sequence; unlike many other config directives, multiple `IdentityFile` values add to the list. `IdentitiesOnly` is needed when you want to stop the agent from offering extra keys. ([OpenBSD Manual Pages][9])

### 6. SSH config editor

This is a bigger problem than it looks.

You need to support:

```txt
Host blocks
Host *
Include
Match
IdentityFile
IdentityAgent
CertificateFile
UserKnownHostsFile
GlobalKnownHostsFile
ProxyJump
ProxyCommand
ForwardAgent
AddKeysToAgent
UseKeychain on macOS
LocalForward / RemoteForward / DynamicForward
ControlMaster / ControlPath / ControlPersist
CanonicalizeHostname
```

OpenSSH config resolution is order-sensitive: command line first, then user config, then system config; first obtained value wins, and more specific host blocks should usually appear before defaults. ([OpenBSD Manual Pages][9])

Big warning: `ssh2-config-rs` is useful, but it admits missing `Match` pattern and token support, while OpenSSH supports `Include`, tokens, and environment expansion in several directives. ([Docs.rs][2])

So for editing, I would **not** rely only on a config parser. Use:

```txt
parser for reading/querying
custom text-preserving editor for writes
backup before mutation
append managed blocks with markers
```

Example managed block:

```sshconfig
# >>> ssh-manager github-work
Host github-work
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519_work
  IdentitiesOnly yes
# <<< ssh-manager github-work
```

### 7. Known hosts manager

Must support:

```txt
list known hosts
find host
show fingerprint
remove host
hash known_hosts
scan host key
compare changed host key
support host:port format [host]:2222
support hashed entries
support GlobalKnownHostsFile
support UserKnownHostsFile
```

Use:

```txt
ssh-key crate          parse known_hosts
ssh-keygen -F host     find host
ssh-keygen -R host     remove host
ssh-keygen -H          hash known_hosts
ssh-keyscan -H host    collect host key
```

`ssh-keyscan` is designed to gather public host keys and build/verify known_hosts files, but scanning alone is **not trust verification**; it collects what the network gives you. ([OpenBSD Manual Pages][12])

Also support `UpdateHostKeys`, because OpenSSH can learn alternate host keys after authentication and update `UserKnownHostsFile`, which matters for host key rotation. ([OpenBSD Manual Pages][9])

### 8. Authorized keys manager

This is separate from `known_hosts`.

Manage:

```txt
~/.ssh/authorized_keys
remote ~/.ssh/authorized_keys
key options
duplicate keys
comments
revoked keys
cert-authority entries
```

OpenSSH `authorized_keys` lines are basically:

```txt
options keytype base64-key comment
```

The options field can restrict keys, including `cert-authority`, forwarding controls, command restrictions, etc. ([OpenBSD Manual Pages][13])

You should support adding/removing public keys by fingerprint, not only by exact line string.

### 9. SSH doctor: local checks

This should be a first-class command:

```bash
ssh-manager doctor
```

Checks:

```txt
~/.ssh exists
~/.ssh owner is current user
~/.ssh not group/world writable
private keys not accessible by others
public keys exist for private keys
config not writable by others
known_hosts readable/writable
authorized_keys permissions sane
IdentityFile paths exist
IdentityFile paths are not accidentally .pub files
duplicate Host aliases
Host blocks with same alias
Host * placed too early
missing IdentitiesOnly for multi-key hosts
ProxyJump host has its own usable config
SSH_AUTH_SOCK exists
agent reachable
agent has expected identities
```

OpenSSH recommends `~/.ssh` be accessible only by the user, requires user config not be writable by others, and ignores private keys if they are accessible by others. ([OpenBSD Manual Pages][14])

### 10. SSH doctor: remote checks

Add:

```bash
ssh-manager doctor remote user@host
```

Checks:

```txt
can resolve host
can connect to port
host key status
which key was offered
which key succeeded
remote user exists
remote home exists
remote ~/.ssh permissions
remote authorized_keys exists
remote authorized_keys contains expected key
remote sshd allows PubkeyAuthentication
remote AuthorizedKeysFile setting
remote StrictModes behavior
remote logs hint
```

`sshd_config` defaults `PubkeyAuthentication` to yes, supports `AuthorizedKeysFile`, and `StrictModes` checks ownership/modes of user files and home directory before accepting login. ([OpenBSD Manual Pages][15])

### 11. Agent manager

Support:

```txt
show agent status
list keys
list public keys
add key
add key with lifetime
add key with confirmation required
remove key
remove all
test key usability
detect stale SSH_AUTH_SOCK
```

OpenSSH agent can hold multiple identities, `ssh` uses them automatically, and private keys/passphrases do not go over the network; operations are performed by the agent. ([man7.org][16])

Also support newer destination-constrained keys:

```bash
ssh-add -h host
ssh-add -h jump>target
```

OpenSSH supports destination constraints since 8.9, but both the remote client/server path must cooperate when forwarding. ([OpenBSD Manual Pages][11])

### 12. Install key to remote

Implement both:

```txt
safe mode: use ssh-copy-id if available
manual mode: ssh remote "mkdir -p ~/.ssh && append key && chmod ..."
```

`ssh-copy-id` appends the local public key to remote `authorized_keys` and sets appropriate permissions. ([Oracle Docs][17])

### 13. Certificates / CA support

Do not skip this if you want “all SSH related”.

Support:

```txt
user certificates
host certificates
CertificateFile
TrustedUserCAKeys
AuthorizedPrincipalsFile
cert-authority in authorized_keys
KRL revocation files
certificate expiry display
certificate principals display
```

`ssh-key` supports OpenSSH certificates and CA support, and `sshd_config` supports `TrustedUserCAKeys` for user certificates. ([Docs.rs][1])

### 14. Security key / FIDO support

Support detection, but use OpenSSH CLI for real operations:

```txt
ed25519-sk
ecdsa-sk
resident keys
touch-required
verify-required
PIN-backed keys
```

`ssh-keygen -K` handles resident FIDO keys, while `sshd_config` has FIDO-specific `PubkeyAuthOptions` like `touch-required` and `verify-required`. ([OpenBSD Manual Pages][10])

### 15. Windows/macOS/Linux differences

Do not make the doctor Unix-only.

Linux/macOS:

```txt
chmod/chown checks
ssh-agent socket
~/.ssh paths
```

macOS:

```txt
UseKeychain
AddKeysToAgent
system keychain behavior
```

Windows:

```txt
ACL checks instead of chmod
OpenSSH agent service
C:\Users\<user>\.ssh
Git Bash / WSL path confusion
```

`ssh2-config-rs` even exposes `UseKeychain` as a macOS-specific attribute. ([Docs.rs][2])

## Final coverage checklist

Your SSH manager should have commands like this:

```bash
ssh-manager key list
ssh-manager key new --type ed25519 --name github-work --comment "hamza@github-work"
ssh-manager key pub ~/.ssh/id_ed25519
ssh-manager key rename old new
ssh-manager key delete github-work --remove-agent --remove-config
ssh-manager key chmod-fix

ssh-manager config list
ssh-manager config get github-work
ssh-manager config add-host github-work --host github.com --user git --key ~/.ssh/id_ed25519_work
ssh-manager config remove-host github-work
ssh-manager config doctor

ssh-manager known-hosts list
ssh-manager known-hosts find github.com
ssh-manager known-hosts scan github.com
ssh-manager known-hosts remove github.com
ssh-manager known-hosts hash

ssh-manager authorized-keys list --remote user@host
ssh-manager authorized-keys add --remote user@host ~/.ssh/id_ed25519.pub
ssh-manager authorized-keys remove --remote user@host --fingerprint SHA256:...

ssh-manager agent status
ssh-manager agent list
ssh-manager agent add ~/.ssh/id_ed25519 --lifetime 8h --confirm
ssh-manager agent remove ~/.ssh/id_ed25519
ssh-manager agent clear

ssh-manager doctor
ssh-manager doctor host github-work
ssh-manager doctor remote user@host
ssh-manager test github-work
```

## The important architectural decision

Use **Rust crates for structure**, but use **OpenSSH CLI as the source of truth** for edge cases.

Best architecture:

```txt
ssh-key
  keys, public/private parsing, fingerprints, authorized_keys, known_hosts

ssh2-config-rs
  read/query OpenSSH config, but not trusted as a complete writer

openssh crate / std::process
  run real ssh, ssh-keygen, ssh-add, ssh-keyscan, ssh -G, ssh -vvv

ssh-agent-client-rs or ssh-agent-lib
  agent listing/removal/addition when you do not want to shell out

portable-pty
  interactive flows when passphrases/prompts are needed
```

The biggest missing piece in the Rust ecosystem is a **complete OpenSSH-compatible, comment-preserving, Include/Match/token-aware config editor**. I would build that yourself as a small AST/text-patcher instead of trusting a parser to rewrite the whole config.

[1]: https://docs.rs/ssh-key/ "ssh_key - Rust"
[2]: https://docs.rs/crate/ssh2-config-rs/latest "ssh2-config-rs 0.7.2 - Docs.rs"
[3]: https://docs.rs/ssh2-config "ssh2_config - Rust"
[4]: https://docs.rs/crate/openssh/latest "openssh 0.11.6 - Docs.rs"
[5]: https://docs.rs/russh/latest/russh/keys/index.html "russh::keys - Rust"
[6]: https://docs.rs/ssh2?utm_source=chatgpt.com "ssh2 - Rust"
[7]: https://docs.rs/ssh-agent-client-rs?utm_source=chatgpt.com "ssh_agent_client_rs - Rust"
[8]: https://docs.rs/portable-pty?utm_source=chatgpt.com "portable_pty - Rust"
[9]: https://man.openbsd.org/ssh_config "ssh_config(5) - OpenBSD manual pages"
[10]: https://man.openbsd.org/ssh-keygen.1 "ssh-keygen(1) - OpenBSD manual pages"
[11]: https://man.openbsd.org/ssh-add.1 "ssh-add(1) - OpenBSD manual pages"
[12]: https://man.openbsd.org/ssh-keyscan.1 "ssh-keyscan(1) - OpenBSD manual pages"
[13]: https://man.openbsd.org/sshd.8 "sshd(8) - OpenBSD manual pages"
[14]: https://man.openbsd.org/ssh.1 "ssh(1) - OpenBSD manual pages"
[15]: https://man.openbsd.org/sshd_config "sshd_config(5) - OpenBSD manual pages"
[16]: https://www.man7.org/linux/man-pages/man1/ssh-agent.1.html "ssh-agent(1) - Linux manual page"
[17]: https://docs.oracle.com/en/operating-systems/oracle-linux/openssh/openssh-CopyingPublicKeystoRemoteServers.html?utm_source=chatgpt.com "Copying Public Keys to Remote Servers"
