# toride-ssh

Async SSH manager library: a unified facade re-exporting the `toride-ssh` key, config, agent, known-hosts, authorized-keys, doctor, forward, certificate, exec, and upload sub-crates behind `SshManager`.

Part of the [toride](https://github.com/freeoxide/toride) workspace.

## Testing without real SSH processes

The `CliRunner`-backed subsystems (keys, agent, doctor, known-hosts) accept
a `MockCliRunner` through `SshManager::with_cli_runner`, so they spawn
nothing in tests. The `certificate` subsystem takes no runner: its
operations spawn real `ssh-keygen` (crates/toride-ssh/crates/certificate/src/lib.rs,
ca.rs, and krl.rs call `toride_ssh_core::runner::ssh_keygen`) whatever
runner the manager carries. The `exec` and `upload` subsystems are built
on `toride_runner::Runner` instead: inject any runner through
`SshManager::exec_with` / `SshManager::upload_with` (a
`toride_runner::fake::FakeRunner` in tests, or a configured runner such as
`DuctRunner::builder().no_default_timeout().build()`). Invocations without a
spec or service timeout run under the default runner's 60 s cap; raise it
with `ExecService::with_timeout` / `UploadService::with_timeout`.

## License

MIT
