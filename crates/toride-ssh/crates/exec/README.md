# toride-ssh-exec

Remote command execution over `ssh` for the toride VPS workflow. `ExecService` owns a `Box<dyn toride_runner::Runner>` the same way `toride_service::ServiceManager` owns one, and runs a command on a host through a `CommandSpec`: `ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=<policy> <host> <element...>`, captured, non-interactive, and testable with `toride-runner`'s `FakeRunner` (the pre-spawn presence probe consults the real `PATH` once per service instance, so the test machine needs an `ssh` binary installed).

Hosts are `toride-ssh-core` `HostSpec` values, parsed under a strict grammar that accepts plain hostnames, IPv4, bare and bracketed IPv6 literals, and `user@` forms, and nothing else. The host-key posture is `toride-ssh-core`'s `HostKeyPolicy` (`Strict`, `AcceptNew`). An `ssh` exit 255 carrying the host-key verification signature in stderr surfaces as the typed `HostKeyVerificationFailed` error rather than a generic command failure, so callers can distinguish "the server is not who you think it is" from "the command failed". That 255 classification is heuristic: a nested inner ssh invoked by the remote command that prints the same signature is misattributed to the outer host.

Exit codes carry two meanings. On a successful connection, exit 1 through 254 is the remote command's own status as ssh relays it, while 255 is ssh's own fatal status (connect failure, authentication failure). `exit_code` is `None` when the local ssh process died by signal, and failure diagnostics render that as `exit signal`, never `exit None`.

Every invocation carries `-o ConnectTimeout=10` (override per service with `with_connect_timeout`), so a blackholed or firewalled host fails at ssh's typed connect error in bounded time instead of blocking until the runner's wall-clock timeout; on a default `DuctRunner` that fallback is 60 s, and a longer per-service cap can be pinned with `with_timeout`.

What it refuses to do:

- There is no API accepting a pre-joined command string. The command is an argv slice, and every element is validated before any process spawns: shell metacharacters, newlines, other control characters, whitespace, glob characters (`*`, `?`, `[`), `$`, `~`, leading `#`, and empty elements are typed rejections that identify the offending position and never echo its value. The strictness is load-bearing: OpenSSH joins the argv into one string that the remote login shell re-tokenizes and glob-expands, so a `touch 'a b'` element would create two remote files and an `*.conf` element would expand against the remote directory if either reached the wire.
- The `ssh` invocation is never assembled through a shell: no `sh -c`, no string joining, `CommandSpec` argv only, with `BatchMode=yes` and stdin wired to the null device so nothing can hang waiting for a prompt. An empty command slice is rejected rather than opening a session.
- Hosts that could be mistaken for `ssh` options or smuggle shell syntax (`-oProxyCommand=...`, `host;other`, whitespace, control characters, overlong input) fail `HostSpec` parsing, so they cannot reach an argv position at all.
- Nothing about the command or its arguments is logged or embedded in error output: failure errors carry the exit code and the runner-scrubbed stderr only, and the invocation is built with redaction enabled so sensitive argv positions (a `--password` value, say) are masked wherever the runner machinery would otherwise display them.

Part of the [toride](https://github.com/freeoxide/toride) workspace and the `toride-ssh` facade.

## License

MIT
