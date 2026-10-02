# toride-runner

Shared command execution for the toride crates: one `Runner` seam every
external command goes through, so callers can swap the real implementation
for a fake in tests.

- `CommandSpec` describes a command (argv, env, cwd, timeout) and carries
  the spec-level policy knobs: `EnvPrecedence`, `PathResolution`,
  `ArgvPolicy`, and `OutputCap` for embedder security postures.
- A sync `Runner` trait with a real `duct`-backed implementation.
- An async `AsyncRunner`/`TokioRunner` pair behind the `tokio-runner`
  feature, plus streaming reads behind `stream`.
- `FakeRunner` (feature `fake`) for hermetic tests, argv redaction, and
  binary discovery helpers.

## Feature flags

| Feature       | Default | Pulls in                  | What it gates                          |
|---------------|:-------:|---------------------------|----------------------------------------|
| `duct-runner` | Yes     | duct, os_pipe             | The real sync runner                   |
| `tokio-runner`| No      | tokio, async-trait        | The async runner                       |
| `stream`      | No      | `tokio-runner`            | Streaming output reads                 |
| `serde`       | No      | serde, serde_json         | Serde on the spec/output types         |
| `fake`        | No      | —                         | The test fake                          |

```toml
[dependencies]
toride-runner = "0.1"
```

[Changelog](CHANGELOG.md) · [Source](https://github.com/freeoxide/toride/tree/master/crates/toride-runner)
