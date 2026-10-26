# HostLink — managed fleet with russh remote execution

Experimental parallel rewrite. The current two-crate SSH milestone is not a drop-in
replacement, release, deployment or installed fleet cutover. The final product MUST also
include Hub-backed inventory, invitations, enrollment, host discovery and revocation. Source baseline: dev 5a1f80b4c44c393dd8cc83faacf0a3ebc49de342.

Target packages:
- hostlink-agent: embedded SSH server, outbound reverse tunnel, SFTP,
  short exec, durable jobs, secure fresh enrollment and Agent-only updater.
- hostlink: Hub-managed host selection/invite/list/revoke plus pinned SSH
  client, exec, transfer, forwarding and resumable test execution.
- hostlink-hub: authoritative identity, route/gateway registry, invitations,
  enrollment, SSH authorization and revocation; **no execution RPC**. See
  [crates/hub/README.md](crates/hub/README.md) for server configuration/API.

Updates must pin the exact Agent artifact SHA-256/version/target, defer active
jobs and reject unsafe roots. Source-exact Windows stopped-process handoff and
rollback are required gates, not currently working features.

The original HostLink `dev` tree remains unchanged. This experimental branch
has runnable CLI binaries; it is **not ready for deployment or fleet migration**.
The managed-fleet target and acceptance gates are in
[docs/MANAGED_FLEET_ARCHITECTURE.md](docs/MANAGED_FLEET_ARCHITECTURE.md)
and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Rust compiler policy

The rewrite follows the installed Rust stable toolchain (currently 1.99.1)
for local Linux/modern Windows checks. The workspace MSRV remains 1.98.1:
raising the minimum is not required just to use a newer compiler. `stable`
is intentionally rolling, not a byte-for-byte reproducible compiler pin;
run `rustc --version` when recording acceptance. The Windows 7 Tier 3 MSVC
targets have no precompiled Rust standard library. Build both Agent and Client
targets with the separately pinned `nightly-2026-08-22`, `cargo-xwin`, and
`build-std`; ordinary Windows MSVC targets are not substitutes. The
source-exact build and PE evidence workflow is documented in
[docs/WIN7_REWRITE_ACCEPTANCE.md](docs/WIN7_REWRITE_ACCEPTANCE.md).

## Development commands

```sh
cargo test --offline --locked --workspace
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo run --offline --locked -p hostlink-agent -- check --config agent.json
cargo run --offline --locked -p hostlink-agent -- run --config agent.json
cargo run --offline --locked -p hostlink-hub -- check --config hub.json
cargo run --offline --locked -p hostlink-hub -- serve --config hub.json
cargo run --offline --locked -p hostlink -- check --config host.json
cargo run --offline --locked -p hostlink -- exec --config host.json --command 'echo hello'
cargo run --offline --locked -p hostlink -- migration preflight --help
```

```sh
scripts/build-win7-candidate.sh \
  --source-sha "$(git rev-parse HEAD)" \
  --output-dir "target/win7-candidate-$(git rev-parse HEAD)"
```

The Win7 builder requires a clean task worktree and a new output directory
inside ignored `target/`. It builds both exact Win7 target triples and writes
PE inspection reports plus a source-bound JSON receipt. A successful cross
build is not native Windows 7 acceptance.

`hostlink migration preflight` inspects bounded local legacy Hub/Controller/Agent snapshots and explicit new Agent/HostSpec configs. It emits a redacted per-host READY/REVIEW/BLOCKED report without SSH, network access, credential conversion, or file writes. See [docs/MIGRATION_RUNBOOK.md](docs/MIGRATION_RUNBOOK.md) for required inputs and manual side-by-side verification/rollback; static readiness is not deployment acceptance.

The Agent listens on loopback and requires an Ed25519 host key and authorized
controller keys. The controller pins the Agent host public key and requires a
private Ed25519 identity. Neither component silently creates or enrolls keys.
Only use disposable current-user fixtures until the native acceptance matrix
passes.

Fresh user enrollment is available as `hostlink-agent enroll`; it uses the Hub
v2 `/v2/enroll` DTO, creates distinct machine and SSH host Ed25519 keys, and
publishes a private config only after validating the Hub response. The Win7
PowerShell 2 and Linux bootstrap scripts require independent exact source pins
for the package ZIP and target-specific verifier sidecar. The sidecar shares the
updater's strict ZIP/member manifest validator, verifies its own bytes match the
ZIP executable, and writes install integrity metadata plus a source-bound
bootstrap receipt before the token prompt. See
[docs/ENROLLMENT.md](docs/ENROLLMENT.md) for the full bootstrap contract and
native acceptance limits.

Durable jobs use the same authenticated SSH connection, with
`hostlink job start`, `hostlink job status` and `hostlink job output`. The job
UUID is printed **before** the first start request; on a lost acknowledgement,
query status by UUID instead of resubmitting. Ordinary SSH `exec` remains
channel-owned and does **not** survive a disconnect.

The client also supports Hub v2 inventory and named host selection while
keeping explicit `--config PATH` as a mutually exclusive option. Start with
`hostlink hub configure`, then use `hostlink list` for registry data or
`hostlink list --check` for bounded pinned SSH probes. See
[docs/CLIENT_HUB.md](docs/CLIENT_HUB.md) for operator commands, private token
requirements, gateway routing and truthful revocation behavior.

The pinned SSH client also supports loopback-only TCP forwarding, local RDP
mapping and target-side TCP probes through `russh` direct-tcpip. See
[docs/TCP_FORWARDING.md](docs/TCP_FORWARDING.md) for commands, deadlines,
concurrency limits and security behavior.

The opt-in process-level managed gateway fixture runs a real child Hub over
trusted local HTTPS, enrolls an Agent, and uses a temporary OpenSSH gateway
whose `AuthorizedKeysFile` includes the Hub-owned v2 projection. It exercises
managed exec, SFTP, durable jobs, forwarding and revocation without touching
user SSH configuration or system services. See
[docs/ISOLATED_GATEWAY.md](docs/ISOLATED_GATEWAY.md) for prerequisites and
limits.

Fresh Agent enrollment can retain an explicitly selected Hub-approved primary
gateway and ordered, independently pinned alternates. Transient transport
failure rotates through those routes with bounded backoff; pin, authentication
and reverse-port authorization failures stop without fallback. See
[docs/MULTI_GATEWAY.md](docs/MULTI_GATEWAY.md) for the route and gateway
authorization contract.

A real Linux HOME Agent↔Client SSH test verifies accepted-once execution,
disconnect/reconnect, binary stdout/stderr and exit code `7`. Native Win7
x64/x86 and Windows Agent-owned durable execution/updater handoff remain
explicit acceptance gates. The Agent-only updater is not removed.
