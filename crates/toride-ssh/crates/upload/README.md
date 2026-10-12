# toride-ssh-upload

One-shot file upload to a remote host for the toride VPS workflow. `UploadService` owns a `Box<dyn toride_runner::Runner>` the same way `toride_service::ServiceManager` owns one, and copies a single existing local regular file to a destination on a host by invoking `sftp -o BatchMode=yes -o StrictHostKeyChecking=<policy> -b <batchfile> <host>`, captured, non-interactive, and testable with `toride-runner`'s `FakeRunner`.

The transfer runs through a batch file holding exactly one `put <local> <remote>` directive, created `0o600` inside a private temporary directory and removed whether the transfer succeeds or fails. sftp batch mode was chosen over `scp` deliberately: `-b` aborts on the first failing directive and never prompts, while `scp` has no equivalent batch discipline, so its failure and prompting semantics would be left to luck. Hosts are `toride-ssh-core` `HostSpec` values, the host-key posture is `toride-ssh-core`'s `HostKeyPolicy` (`Strict`, `AcceptNew`), and an sftp exit 255 carrying the host-key verification signature in stderr surfaces as the typed `HostKeyVerificationFailed` error rather than a generic upload failure, so callers can tell "the server is not who you think it is" from "the transfer failed".

Remote destinations are `RemotePath` values, parsed under a grammar that accepts absolute paths whose bytes cannot break the batch directive — no control characters (newlines included), no whitespace, no quotes, no backslash, no glob metacharacters, no shell metacharacters, no leading dash, nothing over 4096 bytes — and nothing else. A path that could re-tokenize the `put` directive, smuggle a second directive, or glob-expand is a typed rejection whose reason never echoes the input; it cannot reach the batch file at all. Glob characters (`*`, `?`, `[`) are rejected because sftp glob-expands a `put` local path and uploads every matching sibling — a payload named `payload-*.conf` must never silently exfiltrate its directory — and the same grammar is applied to the canonical local path for the same reason.

What it refuses to do:

- There is no API taking a raw remote path string at upload time: `upload` accepts only a validated `RemotePath` and only a validated `HostSpec`, so `-oProxyCommand=...`, `host;other`, whitespace, and control characters fail parsing before an argv position or a batch directive can exist.
- The local side is checked before anything spawns: the file must exist and be a regular file (a missing file or a directory is a typed error), and the canonical local path must itself survive batch-directive validation — spaces, quotes, backslashes, and glob characters are rejections, never silent mis-uploads.
- The sftp invocation is never assembled through a shell — no `sh -c`, no string joining, `CommandSpec` argv only, with `BatchMode=yes` and stdin wired to the null device so nothing can hang waiting for a prompt.
- Neither the uploaded payload nor the remote path leaks into logs or error output: the payload never appears in argv, failure errors carry the exit code and scrubbed stderr only, and any occurrence of the remote or local path in captured stderr is masked before the error is built.

Part of the [toride](https://github.com/freeoxide/toride) workspace and the `toride-ssh` facade.

## License

MIT
