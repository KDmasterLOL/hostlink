# HostLink — SSH-only rewrite

Experimental parallel rewrite. Not a drop-in replacement, release, deployment
or installed fleet cutover. Source baseline: dev 5a1f80b4c44c393dd8cc83faacf0a3ebc49de342.

Target packages:
- hostlink-agent: embedded SSH server, optional outbound reverse tunnel,
  SFTP, short exec, durable job lifecycle and a minimal Agent-only updater.
- hostlink: pinned SSH client, exec, transfer, forwarding and job-based
  test execution/reconnect.

Updates must pin the exact Agent artifact SHA-256/version/target, defer active
jobs and reject unsafe roots. Source-exact Windows stopped-process handoff and
rollback are required gates, not currently working features.

The original HostLink `dev` tree remains unchanged. This experimental branch
has runnable CLI binaries; it is **not ready for deployment or fleet migration**.
The design contract and remaining gates are in `docs/ARCHITECTURE.md`.

## Development commands

```sh
cargo test --offline --locked --workspace
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo run --offline --locked -p hostlink-agent -- check --config agent.json
cargo run --offline --locked -p hostlink-agent -- run --config agent.json
cargo run --offline --locked -p hostlink -- check --config host.json
cargo run --offline --locked -p hostlink -- exec --config host.json --command 'echo hello'
```

The Agent listens on loopback and requires an Ed25519 host key and authorized
controller keys. The controller pins the Agent host public key and requires a
private Ed25519 identity. Neither component silently creates or enrolls keys.
Only use disposable current-user fixtures until the native acceptance matrix
passes.

Durable jobs use the same authenticated SSH connection, with
`hostlink job start`, `hostlink job status` and `hostlink job output`. The job
UUID is printed **before** the first start request; on a lost acknowledgement,
query status by UUID instead of resubmitting. Ordinary SSH `exec` remains
channel-owned and does **not** survive a disconnect.

A real Linux HOME Agent↔Client SSH test verifies accepted-once execution,
disconnect/reconnect, binary stdout/stderr and exit code `7`. Native Win7
x64/x86 and Windows Agent-owned durable execution/updater handoff remain
explicit acceptance gates. The Agent-only updater is not removed.
