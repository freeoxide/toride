# toride-ssh-upload

One-shot file upload to a remote host for the toride VPS workflow. `UploadService` owns a `Box<dyn toride_runner::Runner>` the same way `toride_service::ServiceManager` owns one, and copies existing local regular files to destinations on a host by invoking `sftp -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=<policy> -b <batchfile> <host>`, captured, non-interactive, and testable with `toride-runner`'s `FakeRunner` (the pre-spawn presence probe consults the real `PATH` once per service instance, so the test machine needs an `sftp` binary installed).

The transfer runs through a batch file holding exactly one `put <local> <remote>` directive per file, created `0o600` inside a private temporary directory and removed whether the transfer succeeds or fails. `upload` ships one file; `upload_many` validates every `(local, remote)` pair up front and ships them all in that one batch file, so N files pay one sftp process and one SSH handshake and authentication instead of N. sftp batch mode was chosen over `scp` deliberately: `-b` aborts on the first failing directive and never prompts, while `scp` has no equivalent batch discipline, so its failure and prompting semantics would be left to luck. When a batch aborts, the typed `UploadBatchFailed` error names the failing pair's index when the diagnostic sftp prints identifies one, and carries `None` when it does not, because the index is best-effort.

Hosts are `toride-ssh-core` `HostSpec` values, the host-key posture is `toride-ssh-core`'s `HostKeyPolicy` (`Strict`, `AcceptNew`), and an sftp exit 255 carrying the host-key verification signature in stderr surfaces as the typed `HostKeyVerificationFailed` error rather than a generic upload failure, so callers can tell "the server is not who you think it is" from "the transfer failed". Every invocation carries `-o ConnectTimeout=10` (override per service with `with_connect_timeout`), so a blackholed or firewalled host fails at sftp's typed connect error in bounded time instead of blocking until the runner's wall-clock timeout. An exit without a status (signal death) renders as `exit signal`, never `exit None`.

Remote destinations are `RemotePath` values, parsed under a grammar that accepts absolute paths whose bytes cannot break the batch directive: no control characters (newlines included), no whitespace, no quotes, no backslash, no glob metacharacters, no shell metacharacters, no leading dash, nothing over 4096 bytes, and nothing else. A path that could re-tokenize the `put` directive, smuggle a second directive, or glob-expand is a typed rejection whose reason never echoes the input; it cannot reach the batch file at all. Glob characters (`*`, `?`, `[`) are rejected because sftp glob-expands a `put` local path and uploads every matching sibling: a payload named `payload-*.conf` must never silently exfiltrate its directory, and the same grammar is applied to every canonical local path for the same reason.

Platform support: the local side is unix-only. The canonical local path comes from `fs::canonicalize`, and a Windows backslash path fails batch-directive validation as a typed `InvalidLocalPath` before anything spawns; Windows support is a separate, undecided follow-up.

What it refuses to do:

- There is no API taking a raw remote path string at upload time: `upload` and `upload_many` accept only validated `RemotePath` and `HostSpec` values, so `-oProxyCommand=...`, `host;other`, whitespace, and control characters fail parsing before an argv position or a batch directive can exist.
- The local side is checked before anything spawns: every file must exist and be a regular file (a missing file or a directory is a typed error naming the offending path), and every canonical local path must itself survive batch-directive validation: spaces, quotes, backslashes, and glob characters are rejections, never silent mis-uploads. In a batch, one invalid pair rejects the whole call before any spawn.
- The sftp invocation is never assembled through a shell: no `sh -c`, no string joining, `CommandSpec` argv only, with `BatchMode=yes` and stdin wired to the null device so nothing can hang waiting for a prompt.
- Neither the uploaded payload nor any remote path leaks into logs or error output: the payload never appears in argv, failure errors carry the exit code and scrubbed stderr only, and every occurrence of any uploaded local or remote path in captured stderr is masked as a whole path token before the error is built, whatever the path's length (a `/a` destination is masked in `/a: denied` and left alone inside the unrelated `/archive`).

Part of the [toride](https://github.com/freeoxide/toride) workspace and the `toride-ssh` facade.

## License

MIT
