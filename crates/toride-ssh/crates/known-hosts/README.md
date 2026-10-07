# toride-ssh-known-hosts

Known-hosts file parsing and host-key change detection. Reads and parses `~/.ssh/known_hosts` entries, scans remote hosts via `ssh-keyscan`, and compares the two; provides `KnownHostsService`, `KnownHostsEntry`, `ScannedHostKey`, and `HostKeyChangeReport`.

Part of the [toride](https://github.com/freeoxide/toride) workspace and the `toride-ssh` facade.

## License

MIT
